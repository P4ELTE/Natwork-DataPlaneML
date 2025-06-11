#############
# Arguments #
#############

DEBUG ?= 0

DATA_PATH ?= training_data/improved-cicids/friday
LABEL_CSV_FILE_NAME ?= labels.csv
EVAL_SKIP_PACKETS ?= 0
EVAL_PLAY_SEC ?= -1
MONITORED_FLOW_RATIO ?= 0.05
EVAL_PPS ?= 1000

ATTACK_TYPE_WHITELIST ?= DDoS
PCAP_FILE_NAME ?= ddos.pcap

#ATTACK_TYPE_WHITELIST ?= Portscan
#PCAP_FILE_NAME ?= portscan.pcap

#ATTACK_TYPE_WHITELIST ?= DDoS,Portscan
#PCAP_FILE_NAME ?= ddos_and_portscan.pcap

####################
# End of arguments #
####################

PYTHON_FLAGS = -Werror -Wignore::DeprecationWarning
PYTHON_SCRIPT_FLAGS = --monitored-flow-ratio $(MONITORED_FLOW_RATIO)
ifneq ($(DEBUG), 0)
	PYTHON_SCRIPT_FLAGS += --log-level debug
endif

ORACLE_FLAGS = --oracle-csv $(DATA_PATH)/$(LABEL_CSV_FILE_NAME)
ifneq ($(ATTACK_TYPE_WHITELIST), 0)
	ORACLE_FLAGS += --attack-type-whitelist $(ATTACK_TYPE_WHITELIST)
endif

# This is lazily evaluated, so it doesn't waste time when e.g. only compile is called
PCAP_PACKET_COUNT = $(shell capinfos -cM $(DATA_PATH)/$(PCAP_FILE_NAME) | tail -1 | grep -Po "\d+")
ifeq ($(EVAL_PLAY_SEC), -1)
	EXPECTED_PACKET_COUNT = $(shell expr $(PCAP_PACKET_COUNT) - $(EVAL_SKIP_PACKETS))
else
	EXPECTED_PACKET_COUNT = $(shell expr $(EVAL_PLAY_SEC) \* $(EVAL_PPS))
endif

compile:
	python3 $(PYTHON_FLAGS) -m net_runner $(PYTHON_SCRIPT_FLAGS) --mode compile $(ORACLE_FLAGS)

cli:
	python3 $(PYTHON_FLAGS) -m net_runner $(PYTHON_SCRIPT_FLAGS) --mode cli $(ORACLE_FLAGS)

eval-simulate:
	python3 $(PYTHON_FLAGS) -m net_runner $(PYTHON_SCRIPT_FLAGS) --mode pcap_eval $(ORACLE_FLAGS) \
            --eval-pcap $(DATA_PATH)/$(PCAP_FILE_NAME) \
		    --eval-skip-packets $(EVAL_SKIP_PACKETS) --eval-play-sec $(EVAL_PLAY_SEC) --eval-pps $(EVAL_PPS) \
            --expected-packet-count $(EXPECTED_PACKET_COUNT)

clean:
	mn -c
	rm -rf work/log work/log_* work/pcap work/topology.json work/out

clean-all: clean
	rm -rf work/switch work/cache work/out_for_many_eval

.PHONY: compile cli eval-simulate clean clean-all
