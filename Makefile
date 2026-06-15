# Decepticon — governed deployment.
#
# One-command bring-up of the governed swarm: the governance gateway (single chokepoint
# enforcing agent-integrity + KKI tool-governance) plus the Kali/victim containers. The
# frontend is launched separately because it is an interactive UI.
#
#   make up         # build + start gateway + kali + victim (governed profile)
#   make frontend   # launch the CLI swarm pointed at the gateway (MCP_CONFIG selected)
#   make web        # same, Streamlit UI
#   make down       # stop the governed plane
#   make demo       # gateway demo (no containers/LLMs needed)
#   make verify     # run all integrity self-tests + the AV bundle
#   make audit      # show the two persisted audit chains

COMPOSE := docker compose -f docker-compose.yml -f docker-compose.governed.yml
KKI_PATH ?= ../kali-kimi-interface
export KKI_PATH

.PHONY: up down frontend web demo verify audit gateway-local mint egress-rules egress-verify

# Preview the kernel egress ruleset that KKI_NETWORK_SCOPE produces (no privileges needed).
egress-rules:
	KKI_NETWORK_SCOPE=$(or $(KKI_NETWORK_SCOPE),192.168.56.0/24) \
		python3 deploy/egress/egress_rules.py --dns "$(EGRESS_DNS)" --format nft

# Verify the jail from inside the running gateway container: out-of-scope must be blocked.
egress-verify:
	docker exec governance_gateway /app/deploy/egress/verify_egress.sh $(or $(OUT),1.1.1.1) 80 $(or $(IN),)

# Session-bound identity: mint one token per agent + a matching per-agent MCP config.
# Produces gateway_tokens.json (gateway secret) and mcp_config.gateway.tokens.json (gitignored).
mint:
	python -m governance_gateway.identity --mint

up: mint
	@test -d "$(KKI_PATH)" || (echo "KKI not found at $(KKI_PATH); set KKI_PATH" && exit 1)
	mkdir -p logs
	$(COMPOSE) --profile governed up -d --build
	@echo ""
	@echo "Governed plane up. Gateway: http://localhost:3000/mcp (identity mode: token)"
	@echo "Now launch the swarm pointed at the gateway:  make frontend   (or  make web)"

# Prefer the minted per-agent (token) config; fall back to the token-less template.
GATEWAY_CFG = $(shell test -f mcp_config.gateway.tokens.json && echo mcp_config.gateway.tokens.json || echo mcp_config.gateway.json)

down:
	$(COMPOSE) --profile governed down

# The frontend must use the gateway topology — MCP_CONFIG selects it (mcp_loader honors it).
# Uses the minted per-agent token config when present (so each agent's identity is bound to
# its own token), else the token-less template.
frontend:
	MCP_CONFIG=$(GATEWAY_CFG) python frontend/cli/cli.py

web:
	MCP_CONFIG=$(GATEWAY_CFG) streamlit run frontend/streamlit_app.py

# Run the gateway on the host (dev, no docker). Needs `pip install mcp` and KKI_PATH set.
gateway-local:
	KKI_PATH=$(KKI_PATH) python src/governance_gateway/server.py

demo:
	KKI_PATH=$(KKI_PATH) python examples/gateway_demo.py

verify:
	KKI_PATH=$(KKI_PATH) python -m kki_gov.selftest || KKI_PATH=$(KKI_PATH) PYTHONPATH=src python src/kki_gov/selftest.py
	PYTHONPATH=src python src/swarm_integrity/selftest.py
	PYTHONPATH=src python src/swarm_integrity/run_av_validation.py --output-dir integrity_output
	PYTHONPATH=src python src/swarm_integrity/validate_swarm_bundle.py --output-dir integrity_output

audit:
	@echo "== tool chain ==";  tail -c 400 logs/kki-audit.json 2>/dev/null || echo "(none yet)"
	@echo "\n== agent chain =="; tail -c 400 logs/agent-audit.json 2>/dev/null || echo "(none yet)"
