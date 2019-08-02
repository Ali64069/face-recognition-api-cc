# CodeCommit Repository and Pull Request Notification Solution

This repository contains code to deploy a CICD pipeline which deploys the face recognition API solution.

This Face Recoginition API solution will bridge the request from the API Gateway to the Sage Maker via Lambda function.

This solution alerts on pull request events for all repositories in the account that the solution is deployed into.

Supported notifications: Slack

## Getting Started

It is not possible to deploy this solution locally, only using a CICD pipeline in a CICD aws account or using a SBX to deploy the solution only.See installing options below for instructions on how to deploy this solution.

The CICD pipeline should be used to deploy the solution into the below accounts.

AWS ccounts:

	- cicd (Production account)

### Prerequisites

Before you can use the code in this repository you must:


Install git:

```
brew install git
```

Setup your local client to work CodeCommit:
```
git config --global credential.helper '!aws codecommit credential-helper $@'
git config --global credential.UseHttpPath true

```

Install AWS CLI:
```
pip install awscli

```

Have a CICD account already created with a CICD KMS key available. (Speak to platform about this)

### Deplying to production

To deploy the solution to production we use a CICD pipeline, to deploy the CICD pipeline we use a makefile in the root directory.

IMPORTANT READ FIRST:

	There is a difference between the production solution and sbx solution resources(see Deplying to SBX):
		In SBX the resource names for the SBX resources will include the branch name.
		IN SBX only one test repository is created and is deleted when the stack is deleted.See the CFN condition

		In PRODUCTION the resource names will not include the branch names.
		In PRODUCTION all but the test SBX repository is created, these repositories are not deleted when a stack is deleted.

The following needs to be set for the makefile:

Set access key credentials:

	The following access key need to be added into the ~/.aws/credentials file:
	```
    [jojonomic]
    aws_access_key_id = <access-key>
    aws_secret_access_key = <secret-key>
	```

Set environment variables:

	The AWS cli profile for with access to a CICD account role:
	```
	export AWS_PROFILE=jojonomic
	```

Set the makefile parameter values.

	Ensure the solution name is correct:
	```
	SolutionNaming="jojonomic-microservice"
	```

	Ensure the Locale is correct, used to offset S3 bucket name due to being a global resource:
	```
	Locale="cicd"
	```

	Ensure the Offset is correct,leave blank for production:
	```
	Offset=
	```

	Ensure the BRANCH_NAME is correct:
	```
	BRANCH_NAME=$(shell git rev-parse --abbrev-ref HEAD)
	```

	Ensure the RepositoyName is correct:
	```
	RepositoyName="jojonomic-microservice-cc"
	```

	Ensure the SlackChannel is correct:
	```
	SlackChannel="#pullrequests"
	```

	Ensure the SlackIcon is correct:
	```
	SlackIcon=":aws-codecommit"
	```

	Ensure the SlackURL is correct:
	```
	SlackURL="https://hooks.slack.com/services/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"
	```

To deploy CICD pipeline:
```
$ make deploy
```

To track status on pipeline creation:
```
$ make _events
```

To get output the cloudformation outputs for the CICD pipeline:
```
$ make _output
```

### Updating production solution

To deploy a code update for the CICD pipeline run:
```
$ make update
```

To deploy a code update for the solution simply commit your code to the CodeCommit repository.


###  Running CFN tests

To run a syntax test on CFN templates for the CICD pipeline and solution:
```
$ make test
```

IMPORTANT: To test the solution code deploy the solution in the SBX account.

### Deplying to SBX

To deploy the solution to SBX to test and develop we "DO NOT" use a CICD pipeline, instead use the makefile in the stack directory to deploy the solution directly to the SBX account.

IMPORTANT READ FIRST:

	There is a difference between the production solution and sbx solution resources(see Deplying to production):
		In SBX the resource names for the SBX resources will include the branch name.
		IN SBX only one test repository is created and is deleted when the stack is deleted.See the CFN condition

		In PRODUCTION the resource names will not include the branch names.
		In PRODUCTION all but the test SBX repository is created, these repositories are not deleted when a stack is deleted.

The following needs to be set for the makefile:

Set environment variables:

	The AWS cli profile for with access to a SBX account role:
	```
	export AWS_PROFILE=default
	```

Set the makefile parameter values.

	Ensure the solution name is correct:
	```
	SolutionNaming="jojonomic-microservice"
	```

	Ensure the Offset is correct:
	```
	Offset=$(shell git rev-parse --abbrev-ref HEAD)
	```

	Ensure the Locale is correct, used to offset S3 bucket name due to being a global resource:
	```
	Locale="cicd"
	```

	Ensure the SlackChannel is correct:
	```
	SlackChannel="#pullrequests"
	```

	Ensure the SlackIcon is correct:
	```
	SlackIcon=":aws-codecommit"
	```

	Ensure the SlackURL is correct:
	```
	SlackURL="https://hooks.slack.com/services/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"
	```


To deploy the solution:
```
$ make deploy
```

To track status on the solution deployment:
```
$ make _events
```

To get output the cloudformation outputs:
```
$ make _output
```

### Updating sbx solution

To deploy a solution update run:
```
$ make deploy
```

###  Running CFN tests

To run a syntax test on CFN templates for solution:
```
$ make test
```

## Solution - CodeCommit How To

* [Pull Request Overview](https://docs.aws.amazon.com/codecommit/latest/userguide/pull-requests.html)
* [Creating a pull request](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-create-pull-request.html)
* [View a pull request](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-view-pull-request.html)
* [Review a pull request](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-review-pull-request.html)
* [Update a pull request](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-update-pull-request.html)
* [Close a pull request](https://docs.aws.amazon.com/codecommit/latest/userguide/how-to-close-pull-request.html)
* [Working with commits](https://docs.aws.amazon.com/codecommit/latest/userguide/commits.html)
* [Working with branches](https://docs.aws.amazon.com/codecommit/latest/userguide/branches.html)

##  Folder Structure

pipeline - Contains CFN for CICD pipeline

stack - Contains solution code


## Built With

CICD:
* [CodePipeline](https://aws.amazon.com/codepipeline/?sc_channel=PS&sc_campaign=acquisition_AU&sc_publisher=google&sc_medium=codepipeline_b&sc_content=codepipeline_e&sc_detail=codepipeline&sc_category=code_pipeline&sc_segment=159815530925&sc_matchtype=e&sc_country=AU&s_kwcid=AL!4422!3!159815530925!e!!g!!codepipeline&ef_id=U-GV4gAAAcit3w06:20180514013441:s)
* [S3](https://aws.amazon.com/s3/?sc_channel=PS&sc_campaign=acquisition_AU&sc_publisher=google&sc_medium=s3_b&sc_content=s3_e&sc_detail=aws%20s3&sc_category=s3&sc_segment=175046139817&sc_matchtype=e&sc_country=AU&s_kwcid=AL!4422!3!175046139817!e!!g!!aws%20s3&ef_id=U-GV4gAAAcit3w06:20180514013507:s)

Solution:
* [Lambda](https://aws.amazon.com/lambda/?sc_channel=PS&sc_campaign=acquisition_AU&sc_publisher=google&sc_medium=lambda_b&sc_content=lambda_e&sc_detail=aws%20lambda&sc_category=lambda&sc_segment=221313933066&sc_matchtype=e&sc_country=AU&s_kwcid=AL!4422!3!221313933066!e!!g!!aws%20lambda&ef_id=U-GV4gAAAcit3w06:20180514012145:s)
* [Cloudwatch](https://aws.amazon.com/cloudwatch/?sc_channel=PS&sc_campaign=acquisition_Au&sc_publisher=google&sc_medium=cloudwatch_b&sc_content=cloudwatch_p&sc_detail=cloudwatch&sc_category=cloudwatch&sc_segment=208324178784&sc_matchtype=p&sc_country=AU&s_kwcid=AL!4422!3!208324178784!p!!g!!cloudwatch&ef_id=U-GV4gAAAcit3w06:20180514012222:s)
* [Cloudformation](https://aws.amazon.com/cloudformation/?sc_channel=PS&sc_campaign=acquisition_AU&sc_publisher=google&sc_medium=cloudformation_b&sc_content=cloudformation_e&sc_detail=aws%20cloudformation&sc_category=cloudformation&sc_segment=159811816921&sc_matchtype=e&sc_country=AU&s_kwcid=AL!4422!3!159811816921!e!!g!!aws%20cloudformation&ef_id=U-GV4gAAAcit3w06:20180514012257:s)


