#!/bin/bash
zip -9  CreateAuthChallenge CreateAuthChallenge.js
zip -9  DefineAuthChallenge DefineAuthChallenge.js
zip -9  VerifyAuthChallenge VerifyAuthChallenge.js
zip -9  PreSignup PreSignup.js


aws s3 cp CreateAuthChallenge.zip  s3://billysun-child-singapore
aws s3 cp DefineAuthChallenge.zip  s3://billysun-child-singapore
aws s3 cp VerifyAuthChallenge.zip  s3://billysun-child-singapore
aws s3 cp PreSignup.zip  s3://billysun-child-singapore

