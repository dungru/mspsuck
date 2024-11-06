SHELL := /bin/bash


PY =
_find_py:
ifeq ($(PY),)
	$(eval PY = $(shell pipenv --py 2>/dev/null || which python3))
endif


init:
	@pipenv install --ignore-pipfile
	@pipenv install --ignore-pipfile --dev
	@pipenv run pre-commit install
	@pipenv run pre-commit install --hook-type commit-msg


fmt: _find_py
	@$(PY) -m black .
	@find . -type f -name "*.py" | xargs $(PY) -m reorder_python_imports


lint: _find_py
	@$(PY) -m flake8 .


TYPE = eth_tests
ROOTDIR = $(PWD)/$(TYPE)
MARKER =
ENV =
OPTS =
TESTCASE =
PYTEST_OPTS = --alluredir=allure-results
PYTEST_OPTS += $(TESTCASE)
PYTEST_OPTS += $(OPTS)
ifneq ($(MARKER),)
	PYTEST_OPTS += -k "$(MARKER)"
endif
ifneq ($(ENV),)
	PYTEST_OPTS += --environment="$(ENV)"
endif
ifneq ($(CLINGENV_URL),)
	PYTEST_OPTS += --clingenv_url="$(CLINGENV_URL)"
endif
test: _find_py clean
	@pushd $(ROOTDIR) > /dev/null && ANSIBLE_CONFIG=$(PWD)/ansible.cfg $(PY) -m pytest $(PYTEST_OPTS)


USER_UID ?= $(shell id -u)
ALLURE_PORT ?= $(shell expr $(USER_UID) + 30000)
ALLURE_IP := $(shell hostname -I | awk '{print $$1}')
report:
	@echo "Running Allure server on IP: $(ALLURE_IP) and Port: $(ALLURE_PORT)"
	@allure serve $(ROOTDIR)/allure-results -p $(ALLURE_PORT)
	# @docker run --rm -it \
	#   -p $(ALLURE_IP):$(ALLURE_PORT):8080 \
	#   -v $(ROOTDIR)/allure-results:/opt/allure/results \
	#   sw8-allure-report


clean:
	@find $(PWD) -type f -name '*.py[co]' \
			-o -type d -name __pycache__ \
			-o -type d -name .pytest_cache \
		| xargs rm -rf
	@rm -rf */report
	@rm -rf $(ROOTDIR)/report


REGISTRY = pe1
REPO = sw8-allure-report
TAG = latest
docker:
	docker build --no-cache -t $(REPO) .
