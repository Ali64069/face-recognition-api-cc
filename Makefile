# This Makefile will exist in the 'root' directory *ONLY*

.DEFAULT_GOAL := check-aws-profile

check-aws-profile:
ifndef AWS_PROFILE
	$(error AWS_PROFILE is undefined E.G export AWS_PROFILE=default)
endif

# Parameters
SolutionNaming=jojonomic-face-recognition-api

# Check if the branch equals master if so then set the OFFSET to ""
ifeq ($(shell git rev-parse --abbrev-ref HEAD),master)
    # We are using a CI/CD managed process to deploy codepipeline to CICD account
	Locale=cicd
	# Offset=
	BRANCH_NAME=$(shell git rev-parse --abbrev-ref HEAD)
	RepositoyName=jojonomic-face-recognition-api-cc
#	SlackChannel=<add slack channel e.g #pullrequests>
#	SlackURL=<add slack url e.g https://hooks.slack.com/services/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>
#	SlackIcon=<add slack icon name e.g :aws-codecommit:>
	SlackChannel=
	SlackURL=
	SlackIcon=
else
    # We are developing in Sandbox
	Locale=sbx
	# Offset=$(shell git rev-parse --abbrev-ref HEAD | tr -dc '0-9' | cut -c1-3 )
	BRANCH_NAME=$(shell git rev-parse --abbrev-ref HEAD)
	RepositoyName=jojonomic-face-recognition-api-cc
#	SlackChannel=<add slack channel e.g #pullrequests>
#	SlackURL=<add slack url e.g https://hooks.slack.com/services/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>
#	SlackIcon=<add slack icon name e.g :aws-codecommit:>
	SlackChannel=
	SlackURL=
	SlackIcon=
#
endif


### Deploy Tasks
.PHONY: test
test: check-aws-profile
	aws cloudformation validate-template \
	--template-body file://pipeline/${SolutionNaming}-cicd-pipeline-cf.yaml \
	--region ap-southeast-1 --profile $(AWS_PROFILE)
	aws cloudformation validate-template \
	--template-body file://solution.yaml \
	--region ap-southeast-1 --profile $(AWS_PROFILE)

.PHONY: update
update: check-aws-profile test
	aws cloudformation update-stack \
	--stack-name ${SolutionNaming}-cicd-pipeline-cf \
	--template-body file://pipeline/${SolutionNaming}-cicd-pipeline-cf.yaml \
	--parameters ParameterKey=pSolutionNaming,ParameterValue=$(SolutionNaming) \
	ParameterKey=pLocale,ParameterValue=$(Locale) \
	ParameterKey=pBranchName,ParameterValue=$(BRANCH_NAME) \
	ParameterKey=pRepositoyName,ParameterValue=$(RepositoyName) \
	ParameterKey=pSlackChannel,ParameterValue=$(SlackChannel) \
	ParameterKey=pSlackURL,ParameterValue=$(SlackURL) \
	ParameterKey=pSlackIcon,ParameterValue=$(SlackIcon) \
	--capabilities CAPABILITY_NAMED_IAM --region ap-southeast-1 --profile $(AWS_PROFILE)

.PHONY: deploy
deploy: check-aws-profile test
	aws cloudformation create-stack \
	--stack-name ${SolutionNaming}-cicd-pipeline-cf \
	--template-body file://pipeline/${SolutionNaming}-cicd-pipeline-cf.yaml \
	--parameters ParameterKey=pSolutionNaming,ParameterValue=$(SolutionNaming) \
	ParameterKey=pLocale,ParameterValue=$(Locale) \
	ParameterKey=pBranchName,ParameterValue=$(BRANCH_NAME) \
	ParameterKey=pRepositoyName,ParameterValue=$(RepositoyName) \
	ParameterKey=pSlackChannel,ParameterValue=$(SlackChannel) \
	ParameterKey=pSlackURL,ParameterValue=$(SlackURL) \
	ParameterKey=pSlackIcon,ParameterValue=$(SlackIcon) \
	--capabilities CAPABILITY_NAMED_IAM --region ap-southeast-1 --profile $(AWS_PROFILE)

.PHONY: destroy
destroy: check-aws-profile
	-aws s3 rm s3://${SolutionNaming}-$(Locale)-pipeline-s3 --recursive --region ap-southeast-1 --profile $(AWS_PROFILE)
	-aws s3 rb s3://${SolutionNaming}-$(Locale)-pipeline-s3 --region ap-southeast-1 --profile $(AWS_PROFILE) --force
	aws cloudformation delete-stack \
	--stack-name ${SolutionNaming}-cicd-pipeline-cf \
	--profile $(AWS_PROFILE)

.PHONY: _events
_events: check-aws-profile
	aws cloudformation describe-stack-events \
	--stack-name ${SolutionNaming}-cicd-pipeline-cf \
	--profile $(AWS_PROFILE)

.PHONY: _output
_output: check-aws-profile
	aws cloudformation describe-stacks \
	--stack-name ${SolutionNaming}-cicd-pipeline-cf \
	--profile $(AWS_PROFILE)
