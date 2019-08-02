import {
    getCurrentDateTime,
    getLogger, replacePhoneNumber
} from './Utils'
import { Logger } from 'typescript-logging'
import { Context } from 'aws-lambda'

const AWSXRay = require('aws-xray-sdk')

export class LoggerWrapper {
    private readonly logger: Logger
    private readonly logs: any = {}
    public subSegment: any

    constructor(readonly namespace: string) {
        this.logger = getLogger(namespace)
    }

    public info(message: string): void
    {
        message = replacePhoneNumber(message)
        this.logger.info(message)
        this.logs[getCurrentDateTime()] = `[INFO] ${message}`
    }

    public debug(message: string): void
    {
        message = replacePhoneNumber(message)
        this.logger.debug(message)
        this.logs[getCurrentDateTime()] = `[DEBUG] ${message}`
    }

    public error(e: any): void
    {
        e = replacePhoneNumber(e)
        this.logger.error(e)
        if (this.subSegment)
        {
            this.subSegment.addError(e)
        }
        this.logs[getCurrentDateTime()] = `[ERROR] ${JSON.stringify(e)}`
    }

    public recordLambdaMetadata(event: any, context: Context): void
    {
        this.start()

        const eventString = replacePhoneNumber(JSON.stringify(event, null, 2))
        this.subSegment.addAnnotation('Event', eventString)
        this.debug(`Event: ${eventString}`)

        const contextString = replacePhoneNumber(JSON.stringify(context, null, 2))
        this.subSegment.addAnnotation('Context', contextString)
        this.debug(`Context: ${contextString}`)

        const envString = replacePhoneNumber(JSON.stringify(process.env, null, 2))
        this.subSegment.addAnnotation('Environments', envString)
        this.debug(`Environments: ${envString}`)
    }

    public start(): void
    {
        this.subSegment = AWSXRay.getSegment().addNewSubsegment(this.namespace)
    }

    public close(): void
    {
        this.subSegment.addMetadata('logs', this.logs, this.namespace)
        this.subSegment.close()
    }
}
