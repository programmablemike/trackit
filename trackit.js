'use latest';

import express from 'express';
import { fromExpress } from 'webtask-tools';
import bodyParser from 'body-parser';
import request from 'request';
import { MongoClient } from 'mongodb';
import crypto from 'crypto';
import helmet from 'helmet';
import mongoose from 'mongoose';
import mongooseHidden from 'mongoose-hidden';
const Schema = mongoose.Schema;

// Express middleware
const app = express();
app.use(helmet());
app.use(bodyParser.json({
  strict: true, // Only support JSON objects and arrays
  limit: 1000 // Maximum of 1000 bytes
}));
app.use(
  (req, res, next) => {
    mongoose.connect(req.webtaskContext.secrets.MONGO_URL, {useMongoClient: true});
    next();
  }
);

// Static values
const COLLECTION_NAME = 'trackit';

// Mongoose schemas and models
const GeoJSONPoint = new Schema({
  type: {type: String, default: 'Point', required: true},
  coordinates: {type: Array, min: 2, max: 2}
});
GeoJSONPoint.plugin(mongooseHidden, { defaultHidden: { password: true } });

const GeoJSONFeature = new Schema({
  type: {type: String, default: 'Feature', required: true},
  properties: {
    deviceId: {type: String, hide: true},
    caption: String,
    takenAt: {type: Date, default: Date.now}
  },
  geometry: GeoJSONPoint
}, {collection: COLLECTION_NAME});
GeoJSONFeature.plugin(mongooseHidden, { defaultHidden: { password: true } });

const Feature = mongoose.model('Feature', GeoJSONFeature);

// Hash the Device ID with a secret password. This is to:
//   1) keep device ID's a known and fixed length
//   2) obfuscate the device ID
//   3) prevent injection attacks
function hashedDeviceId(req, id) {
  let hmac = crypto.createHmac('sha256', req.webtaskContext.secrets.DEVICE_KEY);
  return hmac.update(id).digest('hex');
}

// Log an error, set status and send a JSON response
function sendJSONErrorResponse(response, message, status = 500) {
  console.error(message);
  response.status(status).json({error: message})
}

// Adds a new location beacon for the device
// POST data example:
//   {"caption": "Show this on the map",
//    "lat": 32.7157
//    "long": -117.1611}
app.post('/devices/:deviceId/locations',
  (req, res) => {
    var deviceId = hashedDeviceId(req, req.params.deviceId);
    console.log(`Converted deviceId to ${deviceId}`);
    
    // Check for required fields
    if (!req.body.caption) {
      sendJSONErrorResponse(res, 'Missing required field "caption"', 400);
    }
    if (!req.body.lat) {
       sendJSONErrorResponse(res, 'Missing required field "lat"', 400);
    } else {
      if (-90 > req.body.lat || req.body.lat > 90) {
        sendJSONErrorResponse(res, '"lat" value must be in the range (-90, 90)', 400);
      }
    }
    if (!req.body.long) {
      sendJSONErrorResponse(res, 'Missing required field "long"', 400);
    } else {
      if (-180 > req.body.long || req.body.long > 180) {
        sendJSONErrorResponse(res, '"long" value must be in the range (-180, 180)', 400);
      }
    }
    
    // Create a new GeoJSON Feature model
    var model = new Feature({
      properties: {
        deviceId: deviceId,
        caption: req.body.caption
      },
      geometry: {
        coordinates: [req.body.long, req.body.lat]
      }
    });
    
    // Save it to the database
    model.save(deviceId, err => {
      if (err) {
        sendJSONErrorResponse(res, err);
      }
      console.log('Saved document successfully');
      res.json({result: 'success'})
    });
  }
);
  
// Retrieves the history for a device as a GeoJSON
app.get('/devices/:deviceId/history',
  (req, res) => {
    const deviceId = hashedDeviceId(req, req.params.deviceId);
    console.log(`Converted deviceId to ${deviceId}`);
    
    // List all documents for this device
    Feature.find({'properties.deviceId': deviceId}).exec(
      (err, features) => {
        if (err) { sendJSONErrorResponse(res, err) }
        console.log(`Found ${features}`);
        var response = {
          type: 'FeatureCollection',
          features: features.map( feature => feature.toObject() )
        }
        res.set('Content-Type', 'application/vnd.geo+json');
        res.json(response);
      }
    );
  }
);

module.exports = fromExpress(app);