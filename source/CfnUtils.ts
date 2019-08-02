import { request as httpsReq, RequestOptions } from "https"
import { IncomingMessage } from "http"
import { CloudFormationCustomResourceEvent } from "aws-lambda"
import { parse } from "url"

export function https(options: string | RequestOptions, body: string = ""): Promise<IncomingMessage> {
    return new Promise<IncomingMessage>(
        function (resolve, reject) {
            const request = httpsReq(options, (response: IncomingMessage) => {
                resolve(response)
            })
            request.on("error", (error: Error) => {
                reject(error)
            })
            request.write(body)
            request.end()
        })
}

export function cfnHttpsRequestOptions(event: CloudFormationCustomResourceEvent, contentLength: number): RequestOptions {
    const responseUrl = parse(event.ResponseURL)
    return {
        hostname: responseUrl.hostname,
        port: 443,
        path: responseUrl.path,
        method: "PUT",
        headers: {
            'content-type': '',
            'content-length': contentLength
        }

    }
}
