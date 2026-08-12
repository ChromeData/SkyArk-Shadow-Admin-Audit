.PHONY: help clone-skyark aws-up azure-up scan-aws scan-azure score destroy
.DEFAULT_GOAL := help

AWS_TF   := terraform -chdir=terraform/aws
AZURE_TF := terraform -chdir=terraform/azure

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

clone-skyark: ## Clone cyberark/SkyArk into ./vendor (gitignored)
	@test -d vendor/SkyArk || git clone --depth 1 https://github.com/cyberark/SkyArk vendor/SkyArk
	@echo "SkyArk at ./vendor/SkyArk — upstream, not mine. See README attribution."

aws-up: ## Plant the AWS escalation paths
	$(AWS_TF) init -upgrade
	$(AWS_TF) apply

azure-up: ## Plant the Azure escalation paths (needs TF_VAR_throwaway_password)
	$(AZURE_TF) init -upgrade
	$(AZURE_TF) apply

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
