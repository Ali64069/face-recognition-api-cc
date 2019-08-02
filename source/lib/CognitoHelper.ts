import {
  CategoryConfiguration,
  CategoryServiceFactory,
  LogLevel,
} from 'typescript-logging';
import {LoggerWrapper} from './LoggerWrapper';
import {getExistingSecret} from './Utils';
import {
  CreateResourceServerRequest,
  CreateUserPoolClientRequest,
  CreateUserPoolClientResponse,
  CreateUserPoolDomainRequest,
  CreateUserPoolDomainResponse,
  CreateUserPoolRequest,
  CreateUserPoolResponse,
  DeleteUserPoolClientRequest,
  DeleteUserPoolDomainRequest,
  DescribeUserPoolDomainRequest,
  DescribeUserPoolDomainResponse,
  ListUserPoolClientsRequest,
  ListUserPoolClientsResponse,
  ListUserPoolsRequest,
  UserPoolClientDescription,
  UserPoolDescriptionType,
} from 'aws-sdk/clients/cognitoidentityserviceprovider';
import {
  CreateSecretRequest,
  CreateSecretResponse,
  UpdateSecretRequest,
  UpdateSecretResponse,
} from 'aws-sdk/clients/secretsmanager';
import {CognitoIdentityServiceProvider} from 'aws-sdk/clients/browser_default';
import * as AWS from 'aws-sdk';

const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();
const secretsManager = new AWS.SecretsManager();

CategoryServiceFactory.setDefaultConfiguration(
  new CategoryConfiguration(LogLevel.Info)
);

const logger = new LoggerWrapper('lib.CognitoHelper');

export async function generateUserPoolClient(
  userPoolName: string
): Promise<UserPoolDescriptionType> {
  const secretId = `${userPoolName}-client` as string;
  let secretExist = false;

  let secret = await getExistingSecret(secretId);
  logger.info(`secret: ${JSON.stringify(secret)}`);
  if (secret && secret.Name) {
    secretExist = true;
  }

  let recreateUserPoolClient = false;
  if (
    (secretExist &&
      (secret.SecretString === '{}' || secret.SecretString === 'null')) ||
    !secretExist ||
    !(secret.SecretString as string).includes(_getDomain(userPoolName))
  ) {
    recreateUserPoolClient = true;
  }

  logger.info(`Retrieving User Pool = ${userPoolName}`);

  let userPool = await _getUserPool(userPoolName);
  if (userPool && userPool.Name === userPoolName) {
    logger.info(`Existing user pool = ${JSON.stringify(userPool)}`);
  } else {
    logger.info(`Creating new user pool = ${userPoolName}`);

    let userPoolCreateResult = await _createUserPool(userPoolName);
    logger.info(
      `userPoolCreateResult = ${JSON.stringify(userPoolCreateResult)}`
    );

    userPool = await _getUserPool(userPoolName);

    if (userPool && userPool.Name === userPoolName) {
      logger.info(`New userPool = ${JSON.stringify(userPool)}`);
      recreateUserPoolClient = true;
    }
  }

  if (userPool && userPool.Name === userPoolName) {
    logger.info(
      `Refresh resource server and domain of = ${JSON.stringify(userPool)}`
    );
    logger.info(
      `Resource server: ${JSON.stringify(
        await _createResourceServer(userPool)
      )}`
    );
    await _refreshUserPoolDomain(userPool, userPoolName);
  }

  logger.info(`recreateUserPoolClient: ${recreateUserPoolClient}`);

  if (recreateUserPoolClient) {
    const userPoolClient = (await _recreateResourcePoolClient(
      userPool,
      userPoolName
    )) as CreateUserPoolClientResponse;
    logger.info(`userPoolClient: ${JSON.stringify(userPoolClient)}`);

    if (userPoolClient.UserPoolClient) {
      userPoolClient.UserPoolClient.ClientName = _getDomain(userPoolName);
      const secretString = JSON.stringify(userPoolClient) as string;

      logger.info(`secretExist: ${secretExist}`);

      if (!secretExist) {
        const createSecretResult = (await _createSecret(
          secretId,
          secretString
        )) as CreateSecretResponse;
        logger.info(
          `createSecretResult: ${JSON.stringify(createSecretResult)}`
        );
      } else {
        const updateSecretResult = (await _updateSecret(
          secretId,
          secretString
        )) as UpdateSecretResponse;
        logger.info(
          `updateSecretResult: ${JSON.stringify(updateSecretResult)}`
        );
      }
    }
  } else {
    const userPoolClient = await _getResourcePoolClient(userPool, userPoolName);
    logger.info(`userPoolClient: ${JSON.stringify(userPoolClient)}`);
  }

  return userPool;
}

function _getDomain(userPoolName: string): string {
  let domain = `${userPoolName.toLowerCase()}`;
  logger.info(`domain: ${domain}`);

  return domain;
}

async function _getUserPool(
  userPoolName: string
): Promise<UserPoolDescriptionType> {
  const params = {
    MaxResults: 60,
  } as ListUserPoolsRequest;

  logger.info(`Get user pool with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.listUserPools(params, function(
      err,
      userPools
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }

      if (userPools && userPools.UserPools) {
        userPools.UserPools.filter(
          userPool => userPool.Name === userPoolName
        ).forEach(userPool => resolve(userPool));
      }

      resolve({});
    })
  );
}

async function _createUserPool(
  userPoolName: string
): Promise<CreateUserPoolResponse> {
  const params = {
    PoolName: userPoolName,
  } as CreateUserPoolRequest;

  logger.info(`Create user pool with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.createUserPool(params, function(err, data) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _createResourceServer(
  userPool: CognitoIdentityServiceProvider.UserPoolDescriptionType
) {
  const params = {
    Identifier: 'transactions',
    Name: 'transactions',
    UserPoolId: userPool.Id,
    Scopes: [
      {
        ScopeDescription: 'get_tx',
        ScopeName: 'get',
      },
      {
        ScopeDescription: 'post_tx',
        ScopeName: 'post',
      },
    ],
  } as CreateResourceServerRequest;

  logger.info(`Create resource server with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.createResourceServer(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _refreshUserPoolDomain(
  userPool: UserPoolDescriptionType,
  userPoolName: string
) {
  const existingUserPoolDomain = await _getUserPoolDomain(
    userPoolName.toLowerCase()
  );
  logger.info(
    `existingUserPoolDomain: ${JSON.stringify(existingUserPoolDomain)}`
  );

  if (
    existingUserPoolDomain &&
    existingUserPoolDomain.DomainDescription &&
    existingUserPoolDomain.DomainDescription.Domain
  ) {
    await _deleteUserPoolDomain(userPoolName.toLowerCase(), userPool);
  }

  await _createUserPoolDomain(_getDomain(userPoolName), userPool);
}

async function _recreateResourcePoolClient(
  userPool: UserPoolDescriptionType,
  userPoolName: string
): Promise<CreateUserPoolClientResponse> {
  let client = await _getResourcePoolClient(userPool, userPoolName);

  if (client.ClientId) {
    await _deleteUserPoolClient(client, userPool);
  }

  return await _createUserPoolClient(userPoolName, userPool);
}

async function _createSecret(
  secretId: string,
  secretString: string
): Promise<CreateSecretResponse> {
  const params = {
    Name: secretId,
    Description: 'User Pool Client Credential',
    SecretString: secretString,
  } as CreateSecretRequest;

  logger.info(`Create secret with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    secretsManager.createSecret(params, function(err, data) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _updateSecret(
  secretId: string,
  secretString: string
): Promise<UpdateSecretResponse> {
  const params = {
    SecretId: secretId,
    SecretString: secretString,
  } as UpdateSecretRequest;

  logger.info(`Update secret with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    secretsManager.updateSecret(params, function(err, data) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _getResourcePoolClient(
  userPool: UserPoolDescriptionType,
  clientName: string
): Promise<UserPoolClientDescription> {
  const listClients = (await _listUserPoolClients(
    userPool
  )) as ListUserPoolClientsResponse;

  if (listClients.UserPoolClients) {
    for (const client of listClients.UserPoolClients) {
      if (client.ClientName === clientName) {
        return client;
      }
    }
  }

  return {};
}

async function _getUserPoolDomain(
  domain: string
): Promise<DescribeUserPoolDomainResponse> {
  const params = {
    Domain: domain,
  } as DescribeUserPoolDomainRequest;

  logger.info(`Get User Pool Domain = ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.describeUserPoolDomain(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _deleteUserPoolDomain(
  domain: string,
  userPool: CognitoIdentityServiceProvider.UserPoolDescriptionType
): Promise<DescribeUserPoolDomainResponse> {
  const params = {
    Domain: domain,
    UserPoolId: userPool.Id,
  } as DeleteUserPoolDomainRequest;

  logger.info(`Delete User Pool Domain = ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.deleteUserPoolDomain(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _createUserPoolDomain(
  domain: string,
  userPool: CognitoIdentityServiceProvider.UserPoolDescriptionType
): Promise<CreateUserPoolDomainResponse> {
  const params = {
    Domain: domain,
    UserPoolId: userPool.Id,
  } as CreateUserPoolDomainRequest;

  logger.info(`Creating User Pool Domain = ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.createUserPoolDomain(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _deleteUserPoolClient(
  client: CognitoIdentityServiceProvider.UserPoolClientDescription,
  userPool: CognitoIdentityServiceProvider.UserPoolDescriptionType
): Promise<{}> {
  const params = {
    ClientId: client.ClientId,
    UserPoolId: userPool.Id,
  } as DeleteUserPoolClientRequest;

  logger.info(`Delete user pool client with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.deleteUserPoolClient(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _createUserPoolClient(
  userPoolName: string,
  userPool: CognitoIdentityServiceProvider.UserPoolDescriptionType
): Promise<CreateUserPoolClientResponse> {
  const params = {
    ClientName: userPoolName,
    UserPoolId: userPool.Id,
    AllowedOAuthFlows: ['client_credentials'],
    AllowedOAuthFlowsUserPoolClient: true,
    AllowedOAuthScopes: ['transactions/post'],
    GenerateSecret: true,
  } as CreateUserPoolClientRequest;

  logger.info(`Create user pool client with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.createUserPoolClient(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}

async function _listUserPoolClients(
  userPool: CognitoIdentityServiceProvider.UserPoolDescriptionType
): Promise<ListUserPoolClientsResponse> {
  const params = {
    UserPoolId: userPool.Id,
    MaxResults: 60,
  } as ListUserPoolClientsRequest;

  logger.info(`List user pool clients with params: ${JSON.stringify(params)}`);

  return new Promise(resolve =>
    cognitoidentityserviceprovider.listUserPoolClients(params, function(
      err,
      data
    ) {
      if (err) {
        logger.error(`Caught err: ${JSON.stringify(err)}`);
      }
      resolve(data);
    })
  );
}
