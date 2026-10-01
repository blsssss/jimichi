CLUSTER ?= jimichi
NAMESPACE ?= jimichi

.PHONY: check test lint images kind-up kind-load deploy enroll up redeploy start stop down logs stats sweep

check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }
	go vet ./...
	go test -short ./...

test:
	go vet ./...
	go test -count=1 ./...

lint:
	gofmt -l .

images:
	docker build --build-arg TARGET=relay -t jimichi/relay:dev .
	docker build --build-arg TARGET=client -t jimichi/client:dev .

kind-up:
	kind create cluster --config deploy/kind/cluster.yaml
	docker update --restart=no $(CLUSTER)-control-plane $(CLUSTER)-worker $(CLUSTER)-worker2

kind-load: images
	kind load docker-image jimichi/relay:dev --name $(CLUSTER)
	kind load docker-image jimichi/client:dev --name $(CLUSTER)

deploy:
	kubectl apply -f deploy/base/relay.yaml -f deploy/base/network.yaml
	kubectl rollout status -n $(NAMESPACE) deployment -l app=relay
	bash scripts/enroll.sh
	kubectl apply -f deploy/base/client.yaml

enroll:
	bash scripts/enroll.sh

up: kind-up kind-load deploy

redeploy:
	bash scripts/redeploy.sh

start:
	docker start $(CLUSTER)-control-plane $(CLUSTER)-worker $(CLUSTER)-worker2
	kubectl wait --for=condition=Ready nodes --all --timeout=180s
	kubectl -n $(NAMESPACE) rollout status deployment -l app=relay --timeout=180s
	bash scripts/enroll.sh
	kubectl -n $(NAMESPACE) rollout status deployment/client-a --timeout=180s

stop:
	docker stop $(CLUSTER)-worker2 $(CLUSTER)-worker $(CLUSTER)-control-plane

down:
	kind delete cluster --name $(CLUSTER)

sweep:
	bash scripts/sweep.sh -flows 10 -duration 30s -repeats 3 -bins 10ms,100ms

logs:
	kubectl logs -n $(NAMESPACE) -l app=relay --prefix --tail=20

stats:
	bash scripts/stats.sh
