.PHONY: help clone-skyark aws-up azure-up scan-aws scan-azure score destroy
.DEFAULT_GOAL := help

AWS_TF   := terraform -chdir=terraform/aws
AZURE_TF := terraform -chdir=terraform/azure

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

clone-skyark: ## Clone cyberark/SkyArk into ./vendor (gitignored)
	@test -d vendor/SkyArk || git clone --depth 1 https://github.com/cyberark/SkyArk vendor/SkyArk
	@echo "SkyArk at ./vendor/SkyArk, upstream, not mine. See README attribution."

aws-up: ## Plant the AWS escalation paths
	$(AWS_TF) init -upgrade
	$(AWS_TF) apply

azure-up: ## Plant the Azure escalation paths (needs TF_VAR_throwaway_password)
	$(AZURE_TF) init -upgrade
	$(AZURE_TF) apply

aws-up-local: ## Plant the AWS paths on LocalStack, free, no account
	@# LocalStack cannot run AWStealth (it reads creds from the SDK chain with
	@# no endpoint override), so this does not score the scanner. It deploys
	@# every path for free so verify-truth can check the scoring baseline.
	docker run -d --name localstack -p 4566:4566 -e SERVICES=iam,sts,ec2 localstack/localstack:3 || true
	@until curl -s http://localhost:4566/_localstack/health | grep -q '"iam": "available"'; do sleep 3; done
	cd terraform/aws && AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 terraform apply -auto-approve -var use_localstack=true -var skip_org_check=true -var 'allowed_account_ids=["000000000000"]'

verify-truth: ## Check ground-truth.yml against what is actually deployed
	@# The baseline SkyArk gets scored against. Nothing checked it until now.
	@# A path described but not deployed, or deployed but not described, makes
	@# every score computed against it wrong, silently.
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 python scripts/verify_ground_truth.py --endpoint http://localhost:4566

scan-aws: ## Run AWStealth -> findings/awstealth-raw.csv
	pwsh -File scripts/run-awstealth.ps1

scan-azure: ## Run AzureStealth -> findings/azurestealth-raw.csv
	pwsh -File scripts/run-azurestealth.ps1

score: ## Diff scan output against findings/ground-truth.yml
	python3 scripts/score.py

destroy: ## Destroy both environments (filtered on Purpose=security-lab)
	-$(AZURE_TF) destroy -auto-approve
	-$(AWS_TF) destroy -auto-approve
	@echo "Both down. Verify in console that nothing tagged security-lab remains."
