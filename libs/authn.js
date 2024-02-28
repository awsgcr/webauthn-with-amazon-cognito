/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file.
 * This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

const express = require('express');
const router = express.Router();
const { Fido2Lib } = require('fido2-lib');

router.use(express.json());

const f2l = new Fido2Lib({
    timeout: 30*1000*60,
    rpId: '',
    rpName: "my-app",
    challengeSize: 32,
    cryptoParams: [-7]
});

function coerceToArrayBuffer(input) {
  if (typeof input === 'string') {
      // 如果输入是一个 base64 编码的字符串，先将其转换为 Buffer
      input = Buffer.from(input, 'base64');
  }
  if (Buffer.isBuffer(input)) {
      // 如果输入是一个 Buffer 对象，转换为 ArrayBuffer
      return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
  }
  throw new Error("输入类型不正确，需要一个 base64 字符串或 Buffer 对象");
}

function coerceToBase64Url(arrayBuffer) {
  if (arrayBuffer instanceof ArrayBuffer) {
      const uint8Array = new Uint8Array(arrayBuffer);
      const regularBase64 = Buffer.from(uint8Array).toString('base64');
      const base64Url = regularBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      return base64Url;
  } else {
      throw new Error('输入必须是 ArrayBuffer 类型');
  }
}

/**
 * Respond with required information to call navigator.credential.create()
 * Response format:
 * {
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{  
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     allowCredentials : [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }
 **/
router.post('/createCredRequest', async (req, res) => {
  console.log(req);
  f2l.config.rpId = `${req.get('host')}`;
 
  try {
    
    const response = await f2l.attestationOptions();

    console.log(response);

    response.user = {
      displayName: req.body.name,
      id: req.body.username,
      name: req.body.username
    };
    response.challenge = coerceToBase64Url(response.challenge, 'challenge');

    console.log(response.challenge);
    
    response.excludeCredentials = [];
    response.pubKeyCredParams = [];
    // const params = [-7, -35, -36, -257, -258, -259, -37, -38, -39, -8];
    const params = [-7, -257];
    for (let param of params) {
      response.pubKeyCredParams.push({type:'public-key', alg: param});
    }
    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && typeof rr == 'boolean') {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      response.authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      response.attestation = cp;
    }

    console.log(response);

    res.json(response);
  } catch (e) {
    res.status(400).send({ error: e });
  }
});


/**
 * Register user credential.
 * Input format:
 * {
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }
 **/

router.post('/sign-out', async (req, res) => {
    // // 假设你知道要删除的cookie名称
    // const cookies = req.cookies; // 或者 req.headers.cookie 解析
    // for (let cookieName in cookies) {
    //     res.cookie(cookieName, '', { expires: new Date(0) });
    // }
    
  res.json({"msg":"Cookies have been cleared"});  
});

router.post('/parseCredResponse', async (req, res) => {
  f2l.config.rpId = `${req.get('host')}`;
  console.log("parseCredResponse -> " + f2l.config.rpId);

  try {
    const clientAttestationResponse = { response: {} };
    clientAttestationResponse.rawId = coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAttestationResponse.response.clientDataJSON = coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAttestationResponse.response.attestationObject = coerceToArrayBuffer(req.body.response.attestationObject, "attestationObject");
    
    let origin = `https://${req.get('host')}`;

    console.log("origin -> " + origin);

    const attestationExpectations = {
      challenge: req.body.challenge,
      origin: origin,
      factor: "either"
    };

    const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations);

    const credential = {
      credId: coerceToBase64Url(regResult.authnrData.get("credId"), 'credId'),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      aaguid: coerceToBase64Url(regResult.authnrData.get("aaguid"), 'aaguid'),
      prevCounter: regResult.authnrData.get("counter"),
      flags: regResult.authnrData.get("flags")
    };

    // Respond with user info
    res.json(credential);
  } catch (e) {
    res.status(400).send({ error: e.message });
  }
});


module.exports = router;
