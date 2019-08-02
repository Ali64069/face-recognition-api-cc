import {CustomAuthorizerEvent, Context, CustomAuthorizerCallback, CustomAuthorizerResult} from 'aws-lambda'
import * as AWS from 'aws-sdk'
import {GetSecretValueRequest, GetSecretValueResponse} from 'aws-sdk/clients/secretsmanager'
import {IncomingMessage} from 'http'
import {parse} from 'url'
import {RequestOptions} from 'https'
import {CreateUserPoolClientResponse} from 'aws-sdk/clients/cognitoidentityserviceprovider'
import {LoggerWrapper} from '../lib/LoggerWrapper'

const userPoolName = process.env.USER_POOL_NAME as string
const secretId = `${userPoolName}-client` as string
const jwt = require('jsonwebtoken')
const jwkToPem = require('jwk-to-pem')

const secretsManager = new AWS.SecretsManager()

const AWSXRay = require('aws-xray-sdk')
AWSXRay.captureAWSClient(secretsManager)
const https = AWSXRay.captureHTTPs(require('https'))

const logger = new LoggerWrapper('authorizers.ApiGatewayCognito')

export async function handler(event: CustomAuthorizerEvent, context: Context, callback: CustomAuthorizerCallback)
{
    logger.recordLambdaMetadata(event, context)

    let token = event.authorizationToken as string
    let valid = false

    if (token && token.startsWith('Bearer '))
    {
        token = token.replace('Bearer ', '')
        logger.info(`token: ${token}`)

        const userPool = await getUserPoolFromSecret()

        if (userPool.UserPoolClient)
        {
            logger.debug(`UserPoolClient: ${JSON.stringify(userPool.UserPoolClient)}`)

            const userPoolId = userPool.UserPoolClient.UserPoolId
            const region = process.env.REGION as string
            const baseUrl = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
            const iss = `${baseUrl}/.well-known/jwks.json`

            const responseUrl = parse(iss)

            try {

                let options = {
                    hostname: responseUrl.hostname,
                    port: 443,
                    path: responseUrl.path,
                    method: "GET",
                    headers: {
                        'content-type': 'application/json'
                    }} as RequestOptions

                logger.info(`request options: ${JSON.stringify(options)}`)

                const r = await httpsGet(options)
                const bodyString = await getBody(r) as string

                logger.info(`request body response: ${bodyString}`)

                const body = JSON.parse(bodyString)
                let pems = {};
                const keys = body['keys']
                for (let i = 0; i < keys.length; i++) {
                    //Convert each key to PEM
                    const key_id = keys[i].kid
                    const modulus = keys[i].n
                    const exponent = keys[i].e
                    const key_type = keys[i].kty
                    const jwk = {kty: key_type, n: modulus, e: exponent}
                    pems[key_id] = jwkToPem(jwk)
                }

                valid = await validateToken(pems, token, baseUrl)

            }
            catch (e)
            {
                logger.error(e)
            }
        }
    }

    logger.info(`valid: ${valid}`)

    if (valid)
    {
        callback(null, generatePolicy('user', 'Allow', '*'))
    }
    else
    {
        const error = 'Unauthorized'
        logger.error(error)
        callback(error)
    }

    logger.close()
}

async function getBody(r: IncomingMessage): Promise<string> {

    return new Promise<string>(
        function (resolve) {

            let body = ''
            r.on('readable', function () {
                body += r.read()
            })
            r.on('end', function () {
                resolve(body)
            })
        })
}

async function httpsGet(options: RequestOptions): Promise<IncomingMessage>
{
    return new Promise<IncomingMessage>(
        function (resolve, reject) {
            const request = https.get(options, (response: IncomingMessage) => {
                resolve(response)
            })
            request.on("error", (error: Error) => {
                reject(error)
            })

            request.end()
        })
}

async function validateToken(pems, token, iss) {

    logger.info(`pems: ${JSON.stringify(pems)}`)
    logger.info(`decoding token: ${token}`)

    let decodedJwt = jwt.decode(token, {complete: true})

    logger.info(`decodedJwt: ${JSON.stringify(decodedJwt)}`)

    if (!decodedJwt) {
        logger.info('Not a valid JWT token')
        return false
    }

    //Fail if token is not from your UserPool
    if (decodedJwt.payload.iss != iss) {
        logger.info('invalid issuer')
        return false
    }

    //Reject the jwt if it's not an 'Access Token'
    if (decodedJwt.payload.token_use != 'access') {
        logger.info('Not an access token')
        return false
    }

    //Get the kid from the token and retrieve corresponding PEM
    const kid = decodedJwt.header.kid
    const pem = pems[kid]
    if (!pem) {
        logger.info('Invalid access token')
        return false
    }

    let payload = await verifyJwt(token, pem, { issuer: iss })

    if (!payload.sub) {

        logger.info(`Invalid jwt payload: ${JSON.stringify(payload)}`)
        return false
    }

    return true
}

async function verifyJwt(token, pem, issuer): Promise<any> {

    return new Promise((resolve) => {

        jwt.verify(token, pem, issuer, function(err, payload) {

            if (err) {
                resolve({})
            }

            resolve(payload)
        })
    })
}

async function getUserPoolFromSecret(): Promise<CreateUserPoolClientResponse>
{
    const secretParams = {
        SecretId: secretId
    } as GetSecretValueRequest

    let secretString

    try {

        let secret = await secretsManager.getSecretValue(secretParams).promise() as GetSecretValueResponse
        logger.debug(`existing userPoolClient: ${JSON.stringify(secret)}`)

        secretString = secret.SecretString
        return JSON.parse(secretString)
    }
    catch (e)
    {
        logger.error(e)
    }

    return {}
}

let generatePolicy = function(principalId: string, effect: string, resource: string)
{
    let policyDocument

    if (effect && resource) {

        let statementOne = {
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: resource
        }

        policyDocument = {
            Version: '2012-10-17',
            Statement: [statementOne]
        }
    }

    return {
        principalId: principalId,
        policyDocument: policyDocument,
        context: {
            stringKey: 'stringval',
            numberKey: 123,
            booleanKey: true
        }
    } as CustomAuthorizerResult
}
