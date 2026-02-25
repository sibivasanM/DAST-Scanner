FROM ghcr.io/zaproxy/zaproxy:stable

# Install the ZEST scripting add-on during image build so it is always
# available at runtime without requiring internet access in the container.
#
# ZAP add-ons installed here are stored in /home/zap/.ZAP/plugin/ and
# are baked into the image layer — no volume or internet access needed later.
USER zap
RUN zap.sh -cmd -addoninstall zest -silent 2>&1 || true
