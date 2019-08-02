import { CloudFormationCustomResourceEvent, Context, Callback, CloudFormationCustomResourceFailedResponse, CloudFormationCustomResourceSuccessResponse } from "aws-lambda"
import { cfnHttpsRequestOptions, https } from "./CfnUtils";

export type OutputAttributes = { [k: string]: any }
export async function scaffoldHandler(event: CloudFormationCustomResourceEvent, context: Context, callback: Callback, logic: () => Promise<OutputAttributes>) {
    try {
        setupWatchdogTimer(context)
        const outputAttributes = await logic()
        await returnSuccess(event, context, outputAttributes)
    } catch (e) {
        await returnFailure(event, context, e.message)
        callback(e)
    } finally {
        context.done()
    }
}

function setupWatchdogTimer(context: Context) {
    const timeoutHandler = () => {
        console.log('FAILURE due to timeout')
        throw new Error("Timeout")
    }
    // Set timer so it triggers one second before this function would timeout
    setTimeout(timeoutHandler, context.getRemainingTimeInMillis() - 1000)
}

async function returnSuccess(event: CloudFormationCustomResourceEvent, context: Context, data: OutputAttributes = {}) {
    const responseData = JSON.stringify({
        PhysicalResourceId: context.logStreamName,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        Status: "SUCCESS",
        Data: data
    } as CloudFormationCustomResourceSuccessResponse)
    const reqOptions = cfnHttpsRequestOptions(event, responseData.length)
    return await https(reqOptions, responseData)
        .then((d) => {
            console.log(`Success request sent:
            Status: ${d.statusCode}
            Headers: ${JSON.stringify(d.headers)}
            `)
            context.done()
            return d
        }).catch((e: Error) => {
            console.log("Error sending success status. ", e)
            context.fail(e.message)
        })
}
async function returnFailure(event: CloudFormationCustomResourceEvent, context: Context, reason: string = "Unknown") {
    const errData = JSON.stringify({
        PhysicalResourceId: context.logStreamName,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        Status: "FAILED",
        Reason: reason
    } as CloudFormationCustomResourceFailedResponse)
    const reqOptions = cfnHttpsRequestOptions(event, errData.length)
    return await https(reqOptions, errData)
        .then((d) => {
            console.log(`Failure request sent:
            Status: ${d.statusCode}
            Headers: ${d.headers}
            `)
            context.done()
            return d
        }).catch((e: Error) => {
            console.log("Error sending failure status. ", e)
            context.fail(e.message)
        })
}
