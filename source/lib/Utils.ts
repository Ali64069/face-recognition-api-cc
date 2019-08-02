import {
  GetSecretValueRequest,
  GetSecretValueResponse,
  ListSecretsRequest,
  ListSecretsResponse,
  SecretListEntry,
} from 'aws-sdk/clients/secretsmanager';
import * as AWS from 'aws-sdk';
import {GetParametersRequest, Parameter} from 'aws-sdk/clients/ssm';
import {InvocationRequest, InvocationResponse} from 'aws-sdk/clients/lambda';
import {RequestOptions} from 'https';
import {IncomingMessage} from 'http';
import {parse} from 'url';
import {
  CreateUserPoolClientResponse,
  UserPoolClientType,
} from 'aws-sdk/clients/cognitoidentityserviceprovider';
import {
  CategoryConfiguration,
  CategoryServiceFactory,
  DateFormat,
  DateFormatEnum,
  LFService,
  LogFormat,
  LoggerFactoryOptions,
  LogGroupRule,
  LogLevel,
} from 'typescript-logging';
import {MailMessage, PathExtract} from './Namespaces';
import {RestApi, RestApis} from 'aws-sdk/clients/apigateway';
import {v1 as uuid} from 'uuid';
import {DescribeVpcEndpointsResult} from 'aws-sdk/clients/ec2';
import {StartExecutionOutput} from 'aws-sdk/clients/stepfunctions';
import S3 = require('aws-sdk/clients/s3');
import {PutObjectOutput, PutObjectRequest} from 'aws-sdk/clients/s3';

CategoryServiceFactory.setDefaultConfiguration(
  new CategoryConfiguration(LogLevel.Info)
);

const moment = require('moment-timezone');
const querystring = require('querystring');
const https = require('https');
const url = require('url');
const mime = require('mime-types');
const jsonexport = require('jsonexport');

const crypto = require('crypto');
const algorithm = 'aes-256-ctr';
const password = '47787776683e466f334b';

const secretsManager = new AWS.SecretsManager();
const ssm = new AWS.SSM();
const lambda = new AWS.Lambda();
const apigateway = new AWS.APIGateway();
const ec2 = new AWS.EC2({apiVersion: '2016-11-15'});
const stepfunctions = new AWS.StepFunctions();

const options = new LoggerFactoryOptions();
const timeRegion = 'Australia/Sydney';

let logLevel: LogLevel;
switch (process.env.LOG_LEVEL) {
  case 'TRACE':
    logLevel = LogLevel.Trace;
    break;

  case 'DEBUG':
    logLevel = LogLevel.Debug;
    break;

  case 'WARN':
    logLevel = LogLevel.Warn;
    break;

  case 'ERROR':
    logLevel = LogLevel.Error;
    break;

  case 'FATAL':
    logLevel = LogLevel.Fatal;
    break;

  case 'INFO':
  default:
    logLevel = LogLevel.Info;
}

const rule = new LogGroupRule(
  new RegExp('.+'),
  logLevel,
  new LogFormat(
    new DateFormat(DateFormatEnum.YearDayMonthWithFullTime, '/'),
    false
  )
);
options.addLogGroupRule(rule);

const loggerFactory = LFService.createNamedLoggerFactory('coc', options);

export const logger = getLogger('lib.Utils');

export function getLogger(name: string) {
  return loggerFactory.getLogger(name);
}

export function encrypt(text: string): string {
  const cipher = crypto.createCipher(algorithm, password);

  let crypted = cipher.update(text, 'utf8', 'hex');
  crypted += cipher.final('hex');

  return crypted;
}

export function decrypt(text: string): string {
  const decipher = crypto.createDecipher(algorithm, password);

  let dec = decipher.update(text, 'hex', 'utf8');
  dec += decipher.final('utf8');

  return dec;
}

export function getTimeUnitFactor(
  timeUnit: 'ms' | 'sec' | 'min' | 'hr' | 'days'
) {
  let factor = 1;
  switch (timeUnit) {
    case 'sec':
      factor = 1000;
      break;
    case 'min':
      factor = 1000 * 60;
      break;
    case 'hr':
      factor = 1000 * 60 * 60;
      break;
    case 'days':
      factor = 1000 * 60 * 60 * 24;
      break;
    default:
      factor = 1;
      break;
  }
  return factor;
}

export async function getExistingSecret(
  secretId: string
): Promise<GetSecretValueResponse> {
  const secretParams = {
    SecretId: secretId,
  } as GetSecretValueRequest;

  try {
    const params = {
      MaxResults: 60,
    } as ListSecretsRequest;

    let exist = false;
    const allSecrets = (await secretsManager
      .listSecrets(params)
      .promise()) as ListSecretsResponse;

    if (allSecrets.SecretList) {
      for (const i in allSecrets.SecretList) {
        const secret = allSecrets.SecretList[i] as SecretListEntry;
        if (secret.Name === secretId) {
          exist = true;
          break;
        }
      }
    }

    if (exist) {
      return (await secretsManager
        .getSecretValue(secretParams)
        .promise()) as GetSecretValueResponse;
    }
  } catch (e) {
    logger.info(e);
  }

  return {};
}

export async function getParameter(parameterName: string): Promise<Parameter> {
  const params = {
    Names: [parameterName],
  } as GetParametersRequest;

  logger.info(`Get parameters with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    ssm.getParameters(params, (err, parameters) => {
      if (err) {
        logger.info(`Caught err: ${JSON.stringify(err)}`);
      }

      if (
        parameters &&
        parameters.Parameters &&
        parameters.Parameters.length > 0
      ) {
        const parameter = parameters.Parameters[0];
        logger.info(`Parameter exist with value: ${JSON.stringify(parameter)}`);
        resolve(parameter);
      } else {
        resolve({});
      }
    })
  );
}

export async function getRestApi(prefix: string): Promise<RestApi> {
  return new Promise(resolve =>
    apigateway.getRestApis((err, result: RestApis) => {
      if (result.items) {
        result.items.forEach(item => {
          if ((item.name as string).startsWith(prefix)) {
            resolve(item);
          }
        });
      }

      resolve({});
    })
  );
}

export async function getEnvironment(): Promise<string> {
  const envParameter = (await getParameter(
    '/platform/plt-acntmeta/environment'
  )) as Parameter;
  return envParameter.Value as string;
}

export async function getApiKey(): Promise<string> {
  const apiKey = (await getParameter(
    '/dos/coc-cloudfront/x-api-key-header'
  )) as Parameter;
  return apiKey.Value as string;
}

export async function getCondition(): Promise<string> {
  let condition = '-';
  if ((await getEnvironment()) === 'sbx') {
    condition = '-test-';
  }

  return condition;
}

export async function getPrefix(): Promise<string> {
  let mantaroStackName = process.env.MANTARO_STACK_NAME;

  if (!mantaroStackName) {
    mantaroStackName = 'dos-coc-core-mstr';
  }

  let stackNames = mantaroStackName.split('-');

  let suffix = stackNames[3] as any;
  if (suffix !== 'mstr' && parseInt(suffix)) {
    suffix = `ONI-${suffix}`;
    logger.info(`suffix appended: ${suffix}`);
  } else {
    logger.info(`leave original suffix: ${suffix}`);
  }

  return `${stackNames[0]}-${stackNames[1]}-${
    stackNames[2]
  }${await getCondition()}${suffix}`;
}

export function isEmptyObject(obj: any): boolean {
  return !Object.keys(obj).length;
}

export function getBetween(source: string, begin: string, end: string): string {
  const sources = source.split(begin) as string[];

  if (sources.length > 0) {
    const ends = sources[1].split(end) as string[];

    if (ends.length > 0) {
      return ends[0];
    } else {
      return sources[1];
    }
  } else {
    return source;
  }
}

export async function invokeLambda(
  lambdaName: string,
  payload: any
): Promise<string> {
  const params = {
    FunctionName: lambdaName,
    InvocationType: 'RequestResponse',
    LogType: 'Tail',
    Payload: JSON.stringify(payload),
  } as InvocationRequest;

  logger.debug(`lambdaPayload: ${JSON.stringify(payload)}`);
  let response = (await lambda.invoke(params).promise()) as InvocationResponse;
  const logResult = Buffer.from(
    response.LogResult as string,
    'base64'
  ).toString('utf8') as string;
  logger.debug(`logResult: ${logResult}`);

  return logResult;
}

export async function sendRequest(
  options: RequestOptions,
  postData: string | null
): Promise<any> {
  return new Promise(resolve => {
    logger.info(`sending request with options: ${JSON.stringify(options)}`);

    const req = https.request(options, function(res: IncomingMessage) {
      let result = '';
      res.on('data', function(chunk) {
        result += chunk;
      });

      res.on('end', function() {
        resolve(result);
      });

      res.on('error', function(err) {
        resolve(err);
      });
    });

    req.on('error', function(err: Error) {
      logger.error(`${err}`);
    });

    if (postData) {
      req.write(postData);
    }

    req.end();
  });
}

export async function getClientCredential(secretId: string): Promise<string> {
  const secret = (await getExistingSecret(secretId)) as GetSecretValueResponse;

  if (secret && secret.SecretString) {
    const userPool = JSON.parse(
      secret.SecretString
    ) as CreateUserPoolClientResponse;

    if (userPool && userPool.UserPoolClient) {
      const userPoolClient = userPool.UserPoolClient as UserPoolClientType;

      const postData = querystring.stringify({
        grant_type: 'client_credentials',
        scope: 'transactions/post',
      }) as string;

      const responseUrl = parse(`https://${
        userPoolClient.ClientName
      }.auth.ap-southeast-2.amazoncognito.com/oauth2/token` as string);
      const requestOptions = {
        hostname: responseUrl.hostname,
        port: 443,
        path: responseUrl.path,
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          // tslint:disable-next-line: object-literal-key-quotes
          accept: 'application/json',
          // tslint:disable-next-line: object-literal-key-quotes
          authorization: `Basic ${new Buffer(
            `${userPoolClient.ClientId}:${userPoolClient.ClientSecret}`
          ).toString('base64')}`,
          'content-length': Buffer.byteLength(postData),
        },
      } as RequestOptions;

      return sendRequest(requestOptions, postData);
    }
  }

  return '';
}

export function processTitleCase(str: string): string {
  const re = /textToTitleCase\(.*?\)/g;

  let m;
  let result = str;
  while ((m = re.exec(str)) !== null) {
    const text = getBetween(m[0], '(', ')');
    result = result.replace(m[0], textToTitleCase(text));
    logger.debug(`replacing: ${m[0]} with ${textToTitleCase(text)}`);
  }

  return result;
}

export function removeQuotesBetweenText(str: string): string {
  if (str.startsWith(`"`)) {
    str = str.substr(1);
  }

  if (str.startsWith("'")) {
    str = str.substr(1);
  }

  if (str.endsWith(`"`)) {
    str = str.slice(0, -1);
  }

  if (str.endsWith("'")) {
    str = str.slice(0, -1);
  }

  return str;
}

export function textToTitleCase(str: string): string {
  let strs = removeQuotesBetweenText(str)
    .toLowerCase()
    .split(' ') as string[];
  for (let i = 0; i < strs.length; i++) {
    strs[i] = strs[i].charAt(0).toUpperCase() + strs[i].slice(1);
  }

  return `'${strs.join(' ')}'`;
}

export function timestampToDateInTimeZone(timestamp: number) {
  return moment(new Date(timestamp)).tz(timeRegion);
}

export function getCurrentDateInTimeZone() {
  return moment(new Date()).tz(timeRegion);
}

export function toYmdhms(currentMoment: any): any {
  return currentMoment.format('YYYY-MM-DD HH:mm:ss');
}

export function toYmd(currentMoment: any): any {
  return currentMoment.format('YYYY-MM-DD');
}

export function getDayHourMinuteByTimestamp(timestamp: number) {
  const currentMoment = timestampToDateInTimeZone(timestamp);

  return {
    day: (currentMoment.format('dddd') as string).toLowerCase(),
    hours: currentMoment.format('HH'),
    minutes: currentMoment.format('mm'),
  };
}

export function getCurrentDateTime() {
  const currentMoment = getCurrentDateInTimeZone();
  return currentMoment.format('YYYY-MM-DD HH:mm:ss.SSS ZZ');
}

export function getParameterValue(parameters: any[], key: string): string {
  for (const parameter of parameters) {
    if (parameter.key === key) {
      return parameter.value;
    }
  }

  return '';
}

export function replaceAll(
  target: string,
  search: string,
  replacement: string
): string {
  return target.replace(new RegExp(search, 'g'), replacement);
}

export function logPromiseError(params: any = {}, e) {
  logger.error(`Encountered Error: ${e} for params: ${JSON.stringify(params)}`);
  return e;
}

export function sleep(time: number, callback: any) {
  let stop = new Date().getTime();
  while (new Date().getTime() < stop + time) {}
  callback();
}

export function pathProcessor(path: string): PathExtract {
  const delimeter = '/';
  const paths = path.split(delimeter);

  logger.info(`path: ${path}`);

  return {
    first: paths[1],
    second: paths[2],
    third: paths[3],
  } as PathExtract;
}

export function isNumeric(n: any): n is number | string {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

export function isString(x) {
  return Object.prototype.toString.call(x) === '[object String]';
}

export function isUrl(str) {
  const pattern = new RegExp(
    '^(https?:\\/\\/)?' + // protocol
    '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // domain name
    '((\\d{1,3}\\.){3}\\d{1,3}))' + // OR ip (v4) address
    '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // port and path
    '(\\?[;&a-z\\d%_.~+=-]*)?' + // _query string
      '(\\#[-a-z\\d_]*)?$',
    'i'
  ); // fragment locator
  return pattern.test(str);
}

export function replacePhoneNumber(message: string): string {
  return message;
}

export function maskNumber(destinationNumber: string): string {
  const repl = 'XXXX';
  if (destinationNumber.length > 8) {
    const length = destinationNumber.length;
    return destinationNumber.replace(
      destinationNumber.substring(length - 8, length - 4),
      repl
    );
  } else {
    return repl;
  }
}

export async function sendEmail(event: MailMessage): Promise<any> {
  try {
    const buff = new Buffer(event.body);
    const base64data = buff.toString('base64');

    const payload = JSON.stringify({
      to: event.to,
      category: 'CofC',
      batchId: uuid(),
      metadata: {
        title: event.title,
        body: base64data,
      },
    });

    const parsedUrl = url.parse(
      'https://www.healthdirect.gov.au/api/notifications/dispatch/cofc-generic'
    );
    const options = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: parsedUrl.path,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': payload.length,
        'HPP-SITE-ID': 'hin',
      },
    } as RequestOptions;

    logger.info(`Message options: ${JSON.stringify(options)}`);
    let response = await _sendNotificationEmail(options, payload);
    logger.info('Message response: ', response);
    return response;
  } catch (e) {
    logger.info('Error sending email message: ', e);
    return {errorCode: 400, errors: [e.message]} as any;
  }
}

async function _sendNotificationEmail(options, payload): Promise<any> {
  return new Promise(resolve => {
    logger.info(`Sending request... ${JSON.stringify(options)}`);
    logger.info(`Email Payload: ${payload}`);

    const request = https.request(options, function(response) {
      logger.info(`Status: ${response.statusCode}`);
      logger.info(`Headers: ${JSON.stringify(response.headers)}`);
    });

    request.on('error', function(error) {
      logger.info(`Error: ${error}`);
      resolve(error);
    });

    let body = '';
    request.on('readable', function() {
      body += request.read();
    });
    request.on('end', function() {
      resolve(body);
    });

    request.write(payload);
    request.end();
  });
}

export async function getVpcDnsEntries(
  networkInterfacePrefix: string
): Promise<string[]> {
  return new Promise(resolve => {
    return ec2.describeVpcEndpoints(
      {},
      (err, results: DescribeVpcEndpointsResult) => {
        if (err) {
          logger.info(`Caught err: ${JSON.stringify(err)}`);
        }

        const dnsEntries = [] as string[];
        if (
          results &&
          results.VpcEndpoints &&
          results.VpcEndpoints.length > 0
        ) {
          for (const endpoint of results.VpcEndpoints) {
            if (endpoint.Groups) {
              endpoint.Groups.forEach(group => {
                if (
                  (group.GroupName as string).startsWith(
                    networkInterfacePrefix
                  ) &&
                  endpoint.DnsEntries
                ) {
                  endpoint.DnsEntries.forEach(entry => {
                    const dnsName = entry.DnsName as string;
                    if (dnsName.startsWith('vpce-')) {
                      dnsEntries.push(dnsName);
                    }
                  });
                }
              });
            }
          }
        }

        logger.debug(`dnsNames: ${JSON.stringify(dnsEntries)}`);
        resolve(dnsEntries);
      }
    );
  });
}

export async function triggerStepFunction(
  stateMachineArn: string,
  input: string
): Promise<StartExecutionOutput> {
  return new Promise(resolve => {
    const params = {
      stateMachineArn: stateMachineArn,
      input: input,
    };

    return stepfunctions.startExecution(
      params,
      (err, results: StartExecutionOutput) => {
        if (err) {
          logger.info(`Caught err: ${JSON.stringify(err)}`);
        }

        resolve(results);
      }
    );
  });
}

export function getTodayDate(): string {
  return getCurrentDateInTimeZone().format('YYYY-MM-DD');
}

export function getYesterdayDate(): string {
  return getCurrentDateInTimeZone()
    .add(-1, 'days')
    .format('YYYY-MM-DD') as string;
}

export function getLastMonthStartDate(): string {
  return getCurrentDateInTimeZone()
    .date(1)
    .add(-1, 'months')
    .format('YYYY-MM-DD');
}

export function getLastMonthTimestampBegin(): number {
  return getCurrentDateInTimeZone()
    .date(1)
    .add(-1, 'months')
    .hour(0)
    .minute(0)
    .second(0)
    .valueOf();
}

export function getLastMonthEndDate(): string {
  return getCurrentDateInTimeZone()
    .date(1)
    .add(-1, 'days')
    .format('YYYY-MM-DD');
}

export function getLastMonthTimestampEnd(): number {
  return getCurrentDateInTimeZone()
    .date(1)
    .add(-1, 'days')
    .hour(23)
    .minute(59)
    .second(59)
    .valueOf();
}

export function getLastWeekMondayDate(): string {
  return getCurrentDateInTimeZone()
    .day('Monday')
    .add(-7, 'days')
    .format('YYYY-MM-DD');
}

export function getLastWeekSundayDate(): string {
  return getCurrentDateInTimeZone()
    .day('Sunday')
    .format('YYYY-MM-DD');
}

export function getLastWeekMondayTimestampBegin(): number {
  return getCurrentDateInTimeZone()
    .day('Monday')
    .add(-7, 'days')
    .hour(0)
    .minute(0)
    .second(0)
    .valueOf();
}

export function getLastWeekSundayTimestampEnd(): number {
  return getCurrentDateInTimeZone()
    .day('Sunday')
    .hour(23)
    .minute(59)
    .second(59)
    .valueOf();
}

export function getYesterdayTimestampBegin(): number {
  return getCurrentDateInTimeZone()
    .add(-1, 'days')
    .hour(0)
    .minute(0)
    .second(0)
    .valueOf();
}

export function getYesterdayTimestampEnd(): number {
  return getCurrentDateInTimeZone()
    .add(-1, 'days')
    .hour(23)
    .minute(59)
    .second(59)
    .valueOf();
}

export function putObjectIntoS3(
  s3: S3,
  baseDir: string,
  file: string,
  fileData: Buffer
): Promise<PutObjectOutput> {
  const fullPath = `${baseDir}/${file}`;
  const contentType = mime.lookup(fullPath);
  const key = file.replace(`${baseDir}/`, '');

  const params = {
    ACL: 'private',
    Key: key,
    Body: fileData,
    ContentType: contentType,
  } as PutObjectRequest;

  logger.info(`Put ${fullPath} with content type: ${contentType}`);

  return new Promise(resolve =>
    s3.putObject(params, function(err, output) {
      if (err) {
        logger.info(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(output);
    })
  );
}

export function convertJson2Csv(data: any[]): Promise<string> {
  return new Promise(resolve =>
    jsonexport(data, function(err, output) {
      if (err) {
        logger.info(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(output);
    })
  );
}

export function timestampToDate(timestamp: number): any {
  return toYmdhms(timestampToDateInTimeZone(timestamp));
}

export function base64Decode(text: string): string {
  const result = Buffer.from(text as string, 'base64').toString(
    'utf8'
  ) as string;
  logger.debug(`result: ${result}`);
  return result;
}
