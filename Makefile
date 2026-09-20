CLUSTER ?= jimichi
NAMESPACE ?= jimichi

.PHONY: test lint images kind-up kind-load deploy up down logs stats

test:
	go vet ./...
	go test ./...

lint:
	gofmt -l .

images:
	docker build --build-arg TARGET=relay -t jimichi/relay:dev .
	docker build --build-arg TARGET=client -t jimichi/client:dev .

kind-up:
	kind create cluster --config deploy/kind/cluster.yaml

kind-load: images
	kind load docker-image jimichi/relay:dev --name $(CLUSTER)
	kind load docker-image jimichi/client:dev --name $(CLUSTER)

deploy:
	kubectl apply -f deploy/base/relay.yaml
	kubectl rollout status -n $(NAMESPACE) deployment/relay-1
	kubectl rollout status -n $(NAMESPACE) deployment/relay-2
	kubectl rollout status -n $(NAMESPACE) deployment/relay-3
	kubectl apply -f deploy/base/client.yaml

up: kind-up kind-load deploy

down:
	kind delete cluster --name $(CLUSTER)

logs:
	kubectl logs -n $(NAMESPACE) -l app=relay --prefix --tail=20

stats:
	kubectl exec -n $(NAMESPACE) deployment/client-a -- wget -qO- http://relay-1:9100/stats
