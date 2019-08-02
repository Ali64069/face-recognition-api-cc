import {Callback, CloudFormationCustomResourceEvent, Context} from 'aws-lambda'
import {LoggerWrapper} from '../lib/LoggerWrapper'
import {OutputAttributes, scaffoldHandler} from '../CustomResourceHelper'
import {generateUserPoolClient} from '../lib/CognitoHelper'
import {UserPoolDescriptionType} from 'aws-sdk/clients/cognitoidentityserviceprovider'

const logger = new LoggerWrapper('customResources.B2BCredentialGenerator')

export async function handler(event: CloudFormationCustomResourceEvent, context: Context, callback: Callback)
{
    logger.recordLambdaMetadata(event, context)
    try
    {
        await scaffoldHandler(event, context, callback, async () => await _generateB2BCredential())
    }
    catch (e)
    {
        context.fail(`Error: ${e.message}`)
    }
    finally
    {
        logger.close()
    }
}

async function _generateB2BCredential(): Promise<any>
{
    const userPools: string[] = [process.env.USER_POOL_NAME as string]

    const outputs: OutputAttributes =
    {
        outputAttributes: [] as UserPoolDescriptionType[]
    }

    for (const userPool of userPools)
    {
        if (userPool)
        {
            outputs.outputAttributes.push(await generateUserPoolClient(userPool))
        }
    }

    return outputs
}
