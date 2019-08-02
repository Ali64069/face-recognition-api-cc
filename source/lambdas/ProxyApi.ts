import {APIGatewayEvent, Context, ProxyCallback} from 'aws-lambda';
import {LoggerWrapper} from '../lib/LoggerWrapper';
import {PathExtract, Status, ApiResponse} from '../lib/Namespaces';
import {pathProcessor} from '../lib/Utils';
import * as AWS from 'aws-sdk';
import {InvokeEndpointOutput} from 'aws-sdk/clients/sagemakerruntime';

const sagemakerruntime = new AWS.SageMakerRuntime();

const logger = new LoggerWrapper('lambdas.ProxyApi');
const endpointName = 'face-recognition-service';

export async function handler(
  event: APIGatewayEvent,
  context: Context,
  cb?: ProxyCallback
) {
  logger.recordLambdaMetadata(event, context);
  try {
    const path = _processEventPath(event.path) as string;
    logger.info(`Processing path ${path}`);

    const pathExtract = pathProcessor(path) as PathExtract;

    const bodyObject = JSON.parse(event.body as string);
    bodyObject.method_type = pathExtract.first;

    const apiResponse = (await invokeEndpoint(
      bodyObject,
      endpointName
    )) as ApiResponse;

    if (apiResponse) {
      if (apiResponse.status === Status.FAIL) {
        logger.error(
          `Response: ${apiResponse.statusCode}, Message: ${apiResponse.message}`
        );
        _sendResponse(
          cb!,
          apiResponse.statusCode,
          {
            code: apiResponse.statusCode,
            errors: {response: apiResponse.message},
          },
          {}
        );
        return;
      } else {
        logger.info(
          `Response: ${apiResponse.statusCode}, Message: ${JSON.stringify(
            apiResponse.message
          )}`
        );
        _sendResponse(
          cb!,
          apiResponse.statusCode,
          {code: apiResponse.statusCode, response: apiResponse.message},
          {}
        );
        return;
      }
    }

    _sendResponse(
      cb!,
      501,
      {code: 501, errors: {response: 'Not implemented'}},
      {}
    );
    return;
  } finally {
    logger.close();
  }
}

const basePath = `/`;

function _processEventPath(path: string): string {
  let paths = path.split(basePath);
  return `${basePath}${paths[1]}`;
}

function _sendResponse(
  cb: ProxyCallback,
  statusCode: number,
  result: any,
  headers: {[k: string]: string}
) {
  headers['Cache-Control'] = 'no-cache';

  if (result.errors && result.errors.length) {
    const body = JSON.stringify(result.errors, null, 2);
    cb(null, {statusCode, body, headers});
    return;
  } else {
    const body = JSON.stringify(result, null, 2);
    cb(null, {statusCode, body, headers});
  }
}

async function invokeEndpoint(
  body: any,
  endpointName: string
): Promise<ApiResponse | {}> {
  const jsonBody = JSON.stringify(body, null, 2);
  const params = {
    Body: Buffer.from(jsonBody),
    EndpointName: endpointName,
    ContentType: 'application/json',
  };

  logger.info(
    `invoking endpointName: ${endpointName} with JSON body: ${jsonBody}`
  );

  return new Promise(resolve =>
    sagemakerruntime.invokeEndpoint(
      params,
      (err, result: InvokeEndpointOutput) => {
        let apiResponse: ApiResponse;
        if (err) {
          logger.error(`Caught err while putRecord: ${JSON.stringify(err)}`);
          apiResponse = {
            status: Status.FAIL,
            statusCode: 400,
            message: err,
          };
        } else {
          apiResponse = {
            status: Status.SUCCEED,
            statusCode: 200,
            message: JSON.parse(result.Body.toString('utf8')),
          };
        }

        resolve(apiResponse);
      }
    )
  );
}
