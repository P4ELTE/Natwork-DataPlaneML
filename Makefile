#############
# Arguments #
#############

# Set to 1 to enable debug logging
DEBUG ?= 0

# Set to 1 to use centralized inference rather than in-network
CENTRALIZED ?= 0

# Use a custom Python installation if needed
PYTHON_PATH ?= python3

# You can usually leave these as they are
PRE_TRAINED_MODEL_PATH ?= work/pre_trained_model.gz
#MONITORED_FLOWS_NPZ_PATH ?= work/out/Controller-ONLY/monitored_flows.npz
MONITORED_FLOWS_NPZ_PATH ?= work/monitored_flows.npz
LABEL_CSV_FOLDER ?= training_data/improved-cicids/friday
PCAP_FOLDER ?= training_data/improved-cicids/friday
LABEL_CSV_FILE_NAME ?= labels.csv
EVAL_SKIP_PACKETS ?= 0
EVAL_PLAY_SEC ?= -1

# Tofino-specific: which interface to use for tcpreplay
REPLAY_INTERFACE ?= enp33s0f0np0

# Monitoring, packet replaying parameters
MONITORED_FLOW_RATIO ?= 0.05
DISABLE_CONTROLLER_STATS ?= 0
PUSH_STATS_TO_DATABASE ?= 0
EVAL_PPS ?= 1000

# Attack type selection
ATTACK_TYPE_WHITELIST ?= DDoS
PCAP_FILE_NAME ?= ddos.pcap
#ATTACK_TYPE_WHITELIST ?= Portscan
#PCAP_FILE_NAME ?= portscan.pcap
#ATTACK_TYPE_WHITELIST ?= DDoS,Portscan
#PCAP_FILE_NAME ?= ddos_and_portscan.pcap

####################
# End of arguments #
####################

PERF_EVAL_PREFIX = perf stat -e task-clock,cycles,instructions

PYTHON_CMD = $(PYTHON_PATH) -Werror -Wignore::DeprecationWarning

PYTHON_SCRIPT_FLAGS =
ifneq ($(DEBUG), 0)
	PYTHON_SCRIPT_FLAGS += --log-level debug
endif

ORACLE_FLAGS += --csv-path $(LABEL_CSV_FOLDER)/$(LABEL_CSV_FILE_NAME)
ifneq ($(ATTACK_TYPE_WHITELIST), 0)
	ORACLE_FLAGS += --attack-type-whitelist $(ATTACK_TYPE_WHITELIST)
endif

REPORTING_FLAGS = --monitored-flow-ratio $(MONITORED_FLOW_RATIO)
ifeq ($(DISABLE_CONTROLLER_STATS), 0)
	REPORTING_FLAGS += --collect-stats
endif
ifneq ($(PUSH_STATS_TO_DATABASE), 0)
	REPORTING_FLAGS += --stats-database
endif

# The flags of net_runner are mostly just a collection of flags passed to the different components
NET_RUNNER_FLAGS = $(ORACLE_FLAGS) $(REPORTING_FLAGS)
ifneq ($(CENTRALIZED), 0)
	NET_RUNNER_FLAGS += --centralized $(PRE_TRAINED_MODEL_PATH)
endif

# This is lazily evaluated, so it doesn't waste time when e.g. only compile is called
PCAP_PACKET_COUNT = $(shell capinfos -cM $(PCAP_FOLDER)/$(PCAP_FILE_NAME) | tail -1 | grep -Po "\d+")
ifeq ($(EVAL_PLAY_SEC), -1)
	EXPECTED_PACKET_COUNT = $(shell expr $(PCAP_PACKET_COUNT) - $(EVAL_SKIP_PACKETS))
else
	EXPECTED_PACKET_COUNT = $(shell expr $(EVAL_PLAY_SEC) \* $(EVAL_PPS))
endif

clean:
	mn -c || true
	rm -rf work/log work/log_* work/pcap work/topology.json work/out

clean-all: clean
	rm -rf work/switch work/cache work/out_for_many_eval

pcap-extract:
	$(PYTHON_CMD) -m pcap_extractor $(PYTHON_SCRIPT_FLAGS) --out-path $(MONITORED_FLOWS_NPZ_PATH) --overwrite \
            --pcap-path $(PCAP_FOLDER)/$(PCAP_FILE_NAME) --label-csv-path $(LABEL_CSV_FOLDER)/$(LABEL_CSV_FILE_NAME) \
            --attack-type-whitelist $(ATTACK_TYPE_WHITELIST)

centralized-train:
	$(PYTHON_CMD) -m trainer $(PYTHON_SCRIPT_FLAGS) --constraints-type centralized \
            --data-path $(MONITORED_FLOWS_NPZ_PATH) --model-path $(PRE_TRAINED_MODEL_PATH) --overwrite

mininet-compile:
	$(PYTHON_CMD) -m net_runner $(PYTHON_SCRIPT_FLAGS) --mode compile $(NET_RUNNER_FLAGS)

mininet-cli:
	$(PYTHON_CMD) -m net_runner $(PYTHON_SCRIPT_FLAGS) --mode cli $(NET_RUNNER_FLAGS)

mininet-eval:
	$(PYTHON_CMD) -m net_runner $(PYTHON_SCRIPT_FLAGS) --mode pcap_eval $(NET_RUNNER_FLAGS) \
            --eval-pcap $(PCAP_FOLDER)/$(PCAP_FILE_NAME) \
		    --eval-skip-packets $(EVAL_SKIP_PACKETS) --eval-play-sec $(EVAL_PLAY_SEC) --eval-pps $(EVAL_PPS) \
            --expected-packet-count $(EXPECTED_PACKET_COUNT)

tofino-oracle:
	$(PYTHON_CMD) -m oracle $(PYTHON_SCRIPT_FLAGS) $(ORACLE_FLAGS)

tofino-coordinator:
	$(PYTHON_CMD) -m coordinator $(PYTHON_SCRIPT_FLAGS)

tofino-controller:
	if [ "$(CENTRALIZED)" != "0" ]; then \
		$(PERF_EVAL_PREFIX) $(PYTHON_CMD) -m centralized $(PYTHON_SCRIPT_FLAGS) \
				--model-path $(PRE_TRAINED_MODEL_PATH) \
				--topology-path tofino-topology.json \
				--expected-packet-count $(EXPECTED_PACKET_COUNT) \
	; else \
		$(PERF_EVAL_PREFIX) $(PYTHON_CMD) -m controller $(PYTHON_SCRIPT_FLAGS) $(REPORTING_FLAGS) \
				--output-dir work \
				--label-based-forwarding \
				--topology-path tofino-topology.json \
				--expected-packet-count $(EXPECTED_PACKET_COUNT) \
	; fi

tofino-tcpreplay:
	tcpreplay --no-flow-stats -i $(REPLAY_INTERFACE) --pps=$(EVAL_PPS) $(PCAP_FOLDER)/$(PCAP_FILE_NAME)

.PHONY: clean clean-all centralized-train mininet-compile mininet-cli mininet-eval tofino-oracle tofino-coordinator tofino-controller tofino-tcpreplay
