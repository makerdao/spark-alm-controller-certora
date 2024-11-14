PATH := ~/.solc-select/artifacts/:~/.solc-select/artifacts/solc-0.8.21:$(PATH)
certora-rate-limits        :; PATH=${PATH} certoraRun RateLimits.conf$(if $(rule), --rule $(rule),)$(if $(results), --wait_for_results all,)
certora-mainnet-controller :; PATH=${PATH} certoraRun MainnetController.conf$(if $(rule), --rule $(rule),)$(if $(results), --wait_for_results all,)
certora-foreign-controller :; PATH=${PATH} certoraRun ForeignController.conf$(if $(rule), --rule $(rule),)$(if $(results), --wait_for_results all,)
