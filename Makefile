# ShadowPot
#
# Written for GNU Make 3.81, which is what Apple still ships as /usr/bin/make.
# That means no .ONESHELL: every recipe line is its own shell, so multi-step
# recipes chain with && and a failure stops them.
#
#   make              show this help
#   make demo         the whole pipeline on synthetic data, from nothing
#   make test         run the test suite
#   make check        prove a clean clone works end to end
#
# Every target is overridable:
#   make load DB=data/real.db LOGS=~/shadowpot-real-logs

PY       ?= python3
DB       ?= data/shadowpot.db
LOGS     ?= data/sample-logs
OUT      ?= reports/report.md
SEED     ?= 1337
DAYS     ?= 7
SESSIONS ?= 90
TOP      ?= 10

# Bigger, for index measurements. The default sample is far too small for a
# timing to mean anything; see docs/INDEXES.md.
BENCH_DB   ?= data/bench/bench.db
BENCH_LOGS ?= data/bench/logs
BENCH_DAYS ?= 30
BENCH_SESS ?= 350

.DEFAULT_GOAL := help
.PHONY: help sample load report demo test check verify-report bench \
        mysql-schema clean distclean

help:  ## Show this help
	@echo "ShadowPot targets:"
	@echo ""
	@grep -E '^[a-z][a-zA-Z0-9_-]*:.*## ' $(MAKEFILE_LIST) \
		| sed -e 's/:.*## /|/' \
		| awk -F'|' '{ printf "  %-16s %s\n", $$1, $$2 }'
	@echo ""
	@echo "Variables (current values):"
	@echo "  PY=$(PY)   DB=$(DB)"
	@echo "  LOGS=$(LOGS)"
	@echo "  OUT=$(OUT)"
	@echo "  SEED=$(SEED)  DAYS=$(DAYS)  SESSIONS=$(SESSIONS)  TOP=$(TOP)"
	@echo ""
	@echo "Real logs from a deployment (docs/DEPLOY.md) go in their OWN"
	@echo "database. Never the same one as synthetic data: a mixed database"
	@echo "makes every aggregate unusable as evidence."
	@echo "  make load   DB=data/real.db LOGS=~/shadowpot-real-logs"
	@echo "  make report DB=data/real.db OUT=reports/real-report.md"

sample:  ## Generate synthetic Cowrie logs into $(LOGS)
	$(PY) tools/gen_sample_logs.py --out $(LOGS) --seed $(SEED) \
		--days $(DAYS) --sessions-per-day $(SESSIONS)

load:  ## Load $(LOGS) into $(DB). Incremental and idempotent, so safe to repeat
	$(PY) -m shadowpot.ingest --db $(DB) $(LOGS)

report:  ## Build $(OUT) from $(DB)
	$(PY) -m shadowpot.report --db $(DB) --out $(OUT) --top $(TOP)

demo:  ## sample + load + report, from nothing. The 60-second tour
	@echo "==> generating synthetic logs"
	@$(MAKE) --no-print-directory sample
	@echo "==> loading"
	@$(MAKE) --no-print-directory load
	@echo "==> reporting"
	@$(MAKE) --no-print-directory report
	@echo ""
	@echo "Done. Read $(OUT). It opens with a SYNTHETIC SAMPLE DATA banner,"
	@echo "because every number in it came from a generator."

test:  ## Run the test suite
	$(PY) -W error::ResourceWarning -m unittest discover -s tests -t . -v

check:  ## Prove a clean clone works: tests, then the pipeline in a scratch dir
	@echo "==> test suite"
	@$(MAKE) --no-print-directory test 2>&1 | tail -3
	@echo "==> full pipeline into a scratch directory"
	@mkdir -p .check
	$(PY) tools/gen_sample_logs.py --out .check/logs --seed 1 --days 2 \
		--sessions-per-day 20 --quiet --force
	$(PY) -m shadowpot.ingest --db .check/check.db .check/logs --quiet
	$(PY) -m shadowpot.report --db .check/check.db --out .check/report.md --quiet
	@$(MAKE) --no-print-directory verify-report OUT=.check/report.md
	@echo "==> clean-clone pipeline OK (scratch kept in .check/, gitignored)"

verify-report:  ## Assert $(OUT) exists and is labelled correctly
	@test -s "$(OUT)" || { echo "FAIL: $(OUT) is missing or empty"; exit 1; }
	@grep -q "SYNTHETIC SAMPLE DATA" "$(OUT)" \
		|| { echo "FAIL: $(OUT) carries no synthetic banner, but was built"; \
		     echo "      from generated data. Refusing to pass."; exit 1; }
	@echo "OK: $(OUT) is present and carries the synthetic banner"

bench:  ## Measure candidate indexes and regenerate docs/INDEXES.md
	@echo "==> building a large database; the 7-day sample is too small to time"
	@mkdir -p $(dir $(BENCH_DB))
	$(PY) tools/gen_sample_logs.py --out $(BENCH_LOGS) --days $(BENCH_DAYS) \
		--sessions-per-day $(BENCH_SESS) --seed 7 --quiet --force
	$(PY) -m shadowpot.ingest --db $(BENCH_DB) $(BENCH_LOGS) --quiet
	$(PY) tools/bench_indexes.py --db $(BENCH_DB)

mysql-schema:  ## Apply the MySQL schema. Needs MYSQL_USER and MYSQL_DB
	@test -n "$(MYSQL_USER)" || { echo "set MYSQL_USER=..."; exit 1; }
	@test -n "$(MYSQL_DB)"   || { echo "set MYSQL_DB=... (create it first)"; exit 1; }
	@echo "==> this path has never been run against a live server; see the"
	@echo "    header of schema/schema.mysql.sql"
	mysql -u $(MYSQL_USER) -p $(MYSQL_DB) < schema/schema.mysql.sql
	mysql -u $(MYSQL_USER) -p $(MYSQL_DB) < schema/indexes.mysql.sql
	@echo "==> applied. Now run the round trip:"
	@echo "    SHADOWPOT_MYSQL_DSN='host=localhost;user=$(MYSQL_USER);database=$(MYSQL_DB)' \\"
	@echo "        $(PY) -m unittest tests.test_schema -v"

clean:  ## Remove generated logs, databases and the working report
	$(PY) tools/clean.py
	@echo "Kept: reports/sample-report.md (committed) and data/real.db if any."

distclean:  ## clean, plus EVERY database. Needs CONFIRM=yes
	@test "$(CONFIRM)" = "yes" || { \
		echo "distclean deletes data/real.db too, and real honeypot logs are"; \
		echo "NOT reproducible: you cannot regenerate a week of attacks."; \
		echo "Re-run as:  make distclean CONFIRM=yes"; exit 1; }
	$(PY) tools/clean.py --all
