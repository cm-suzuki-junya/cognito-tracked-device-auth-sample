const {
  CognitoIdentityProviderClient,
  AdminRespondToAuthChallengeCommand, AdminInitiateAuthCommand,
  ConfirmDeviceCommand
} = require("@aws-sdk/client-cognito-identity-provider");
const { createHmac } = require("crypto");
const AuthenticationHelper = require("amazon-cognito-identity-js/lib/AuthenticationHelper").default;
const BigInteger = require("amazon-cognito-identity-js/lib/BigInteger").default;
const DateHelper = require("amazon-cognito-identity-js/lib/DateHelper").default;
require('dotenv').config();

const USER_POOL_ID = process.env.USER_POOL_ID;
const USER_POOL_NAME = USER_POOL_ID.split('_')[1];
const CLIENT_ID = process.env.CLIENT_ID;

const authenticationHelper = new AuthenticationHelper(USER_POOL_NAME);
const client = new CognitoIdentityProviderClient({region: 'ap-northeast-1'});

const dateHelper = new DateHelper();
const dateNow = dateHelper.getNowString();

(async () => {
  const [_, __, mode] = process.argv;
  switch(mode){
    case "user":
      authNoDevice()
      break;
    case "device":
      await authUseDevice();
      break;
    default:
      break;
  }
})();


/**
 * ユーザIDとパスワードのみで認証させる
 * 
 */
async function authNoDevice() {
  const userName = process.env.userName;
  const userPassword = process.env.userPassword;
  let srp_a;
  authenticationHelper.getLargeAValue((_, value) => srp_a = value.toString(16));
  const initiateRes = await adminInitiateAuth({
    USERNAME: userName,
    SRP_A: srp_a
  });

  let userSig = createSig(userName, userPassword, initiateRes.ChallengeParameters);
  const passwordChallengeRes = await doChallenge(initiateRes.ChallengeName, {
    USERNAME: userName,
    PASSWORD_CLAIM_SIGNATURE: userSig,
    PASSWORD_CLAIM_SECRET_BLOCK: initiateRes.ChallengeParameters.SECRET_BLOCK,
    SRP_A: srp_a,
    TIMESTAMP: dateNow
  });
  console.log("--------User Auth Result--------");
  console.log(passwordChallengeRes);


  console.log("--------Device Parameters--------");
  await confirmDevice(passwordChallengeRes.AuthenticationResult);
  let deviceInfo = JSON.parse(JSON.stringify(passwordChallengeRes.AuthenticationResult.NewDeviceMetadata));
  deviceInfo["DevicePassword"] = authenticationHelper.randomPassword;
  console.log(deviceInfo);
}

/**
 * トラッキングされたデバイスを利用した認証
 * 
 */
async function authUseDevice(){
  const userName = process.env.userName;
  const userPassword = process.env.userPassword;
  const deviceGroupKey = process.env.deviceGroupKey;;
  const deviceKey = process.env.deviceKey;
  const devicePassword = process.env.devicePassword;

  let srp_a;
  authenticationHelper.getLargeAValue((_, value) => srp_a = value.toString(16));

  const deviceInitiateRes = await adminInitiateAuth({
    USERNAME: userName,
    SRP_A: srp_a,
    DEVICE_KEY: deviceKey
  });

  const userSig = createSig(userName, userPassword, deviceInitiateRes.ChallengeParameters);
  const passwordChallengeRes = await doChallenge(deviceInitiateRes.ChallengeName, {
    USERNAME: userName,
    PASSWORD_CLAIM_SIGNATURE: userSig,
    PASSWORD_CLAIM_SECRET_BLOCK: deviceInitiateRes.ChallengeParameters.SECRET_BLOCK,
    SRP_A: srp_a,
    DEVICE_KEY: deviceKey,
    TIMESTAMP: dateNow
  });

  //この時点ではトークンは発行されない
  console.log("--------User Auth Result--------");
  console.log(passwordChallengeRes);

  authenticationHelper.poolName = deviceGroupKey;  
  //DEVICE_SRP_AUTH
  const deviceChallengeRes = await doChallenge(passwordChallengeRes.ChallengeName,{
    USERNAME: userName,
    SRP_A: srp_a,
    DEVICE_KEY: deviceKey
  }, passwordChallengeRes.Session);
  const deviceSig = createSig(deviceKey, devicePassword,deviceChallengeRes.ChallengeParameters, deviceGroupKey);

  //DEVICE_PASSWORD_VERIFIER
  const deviceAuthChallengeRes = await doChallenge(deviceChallengeRes.ChallengeName, {
    USERNAME: userName,
    PASSWORD_CLAIM_SIGNATURE: deviceSig, 
    PASSWORD_CLAIM_SECRET_BLOCK: deviceChallengeRes.ChallengeParameters.SECRET_BLOCK,
    DEVICE_KEY: deviceKey,
    TIMESTAMP: dateNow
  });

  console.log("--------Device Auth Result--------");
  console.log(deviceAuthChallengeRes);
}

/**
 * AdminInitiateAuthCommandを実行する
 * @returns {AdminInitiateAuthCommandOutput}
 */
async function adminInitiateAuth(authParams) {
  return await client.send(new AdminInitiateAuthCommand({
    ClientId: CLIENT_ID,
    UserPoolId: USER_POOL_ID,
    AuthFlow: "USER_SRP_AUTH",
    AuthParameters: authParams
  }))
}

/**
 * 署名情報を作成する
 * @param {string} user 
 * @param {string} password 
 * @param {ChallengeParameters} challengeParameters 
 * @param {string} overridePool DEVICE_PASSWORD_VERIFIERの演算時にuserPoolをDeviceGroupKeyにさせたいので無理やり
 * @returns 
 */
function createSig(user, password, challengeParameters, overridePool = undefined){
  const tmpPoolName = authenticationHelper.poolName;
  if (overridePool !== undefined) {  
    authenticationHelper.poolName = overridePool;
  }
  let hkdf;
  authenticationHelper.getPasswordAuthenticationKey(
    user,
    password,
    new BigInteger(challengeParameters.SRP_B, 16),
    new BigInteger(challengeParameters.SALT, 16),
    (_, res) => {hkdf = res}
  );
  const msg = Buffer.concat([
    Buffer.from(authenticationHelper.poolName, 'utf-8'),
    Buffer.from(user, 'utf-8'),
    Buffer.from(challengeParameters.SECRET_BLOCK, 'base64'),
    Buffer.from(dateNow, 'utf-8')
  ]);
  authenticationHelper.poolName = tmpPoolName;
  return createHmac('sha256', hkdf).update(msg).digest('base64');
}

/**
 * AdminRespondToAuthChallengeCommandを実行する
 * @param {ChallengeName} challengeName 
 * @param {ChallengeParameters} challengeParameters 
 * @param {string?} session
 * @returns 
 */
async function doChallenge(challengeName, challengeParameters, session = undefined) {
  return await client.send(
    new AdminRespondToAuthChallengeCommand({
      ClientId: CLIENT_ID, 
      UserPoolId: USER_POOL_ID, 
      ChallengeName: challengeName,
      ChallengeResponses: challengeParameters,
      Session: session
    })
  );
}

/**
 * confirmDeviceを実行してデバイスを登録する
 * @param {AuthenticationResult} tokens 
 * @returns 
 */
async function confirmDevice(tokens){
  return await client.send(
    new ConfirmDeviceCommand({
      AccessToken: tokens.AccessToken,
      DeviceKey: tokens.NewDeviceMetadata.DeviceKey,
      DeviceName: "new-device",
      DeviceSecretVerifierConfig: getDeviceSecretVerifierConfig(tokens.NewDeviceMetadata.DeviceGroupKey, tokens.NewDeviceMetadata.DeviceKey)
    })
  );
}

/**
 * deviceGroupKeyとDeviceKeyからからDeviceSecretVerifierConfigを作成し返却する
 * @param {string} deviceGroupKey 
 * @returns {DeviceSecretVerifierConfig}
 */
function getDeviceSecretVerifierConfig(deviceGroupKey, deviceKey){
  authenticationHelper.generateHashDevice(
    deviceGroupKey,
    deviceKey,
    (err, _) => {} 
  );
  return {
    Salt: Buffer.from(authenticationHelper.getSaltDevices(),'hex').toString('base64'),
    PasswordVerifier: Buffer.from(authenticationHelper.getVerifierDevices(), 'hex').toString('base64')
  };
}