#########################################
# Building Docker Image
#
# This uses a multi-stage build file. The first stage is a builder (that might
# be large in size). After the build has succeeded, the statically linked
# binary is copied to a new image that is optimized for size.
#########################################

docker-prepare:
	# Ensure, we can build for ARM architecture
	[ -f /proc/sys/fs/binfmt_misc/qemu-arm ] || docker run --rm --privileged docker/binfmt:a7996909642ee92942dcd6cff44b9b95f08dad64

	# Register buildx builder
	mkdir -p $$HOME/.docker/cli-plugins

	wget -O $$HOME/.docker/cli-plugins/docker-buildx https://github.com/docker/buildx/releases/download/v0.3.1/buildx-v0.3.1.linux-amd64
	chmod +x $$HOME/.docker/cli-plugins/docker-buildx

	$$HOME/.docker/cli-plugins/docker-buildx create --name mybuilder --platform amd64 --platform arm || true
	$$HOME/.docker/cli-plugins/docker-buildx use mybuilder

.PHONY: docker-prepare

#################################################
# Releasing Docker Images
#
# Using the docker build infrastructure, this section is responsible for
# logging into docker hub.
#################################################

# Rely on DOCKER_USERNAME and DOCKER_PASSWORD being set inside the CI or
# equivalent environment
docker-login:
	$Q docker login -u="$(DOCKER_USERNAME)" -p="$(DOCKER_PASSWORD)"

.PHONY: docker-login

#################################################
# Targets for different type of builds
#################################################

DOCKER_IMAGE_NAME = smallstep/step-cli
PLATFORMS = --platform amd64 --platform 386 --platform arm --platform arm64

define DOCKER_BUILDX
	# $(1) -- Image Tag
	# $(2) -- Push (empty is no push | --push will push to dockerhub)
	$$HOME/.docker/cli-plugins/docker-buildx build . --progress plain -t $(DOCKER_IMAGE_NAME):$(1) -f docker/Dockerfile $(PLATFORMS) $(2)
endef

# For non-master builds don't build the docker containers.
docker-branch:

# For master builds create the docker containers but don't push them.
docker-master: docker-prepare
	$(call DOCKER_BUILDX,latest,)

# For all builds with a release candidate tag build and push the containers.
docker-release-candidate: docker-prepare docker-login
	$(call DOCKER_BUILDX,$(VERSION),--push)

# For all builds with a release tag build and push the containers.
docker-release: docker-prepare docker-login
	$(call DOCKER_BUILDX,latest,--push)
	$(call DOCKER_BUILDX,$(VERSION),--push)

.PHONY: docker-branch docker-master docker-release-candidate docker-release
