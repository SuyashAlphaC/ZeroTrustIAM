'use strict';

let sdk;

function initTracing() {
  if (process.env.OTEL_SDK_DISABLED === 'true') return;
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return;

  try {
    const { NodeSDK } = require('@opentelemetry/sdk-node');
    const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
    const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
    const { Resource } = require('@opentelemetry/resources');

    const resource = Resource.default().merge(new Resource({
      'service.name': process.env.OTEL_SERVICE_NAME || 'zt-iam-policy-engine',
    }));

    const exporter = new OTLPTraceExporter({
      url: endpoint.endsWith('/v1/traces') ? endpoint : `${endpoint.replace(/\/$/, '')}/v1/traces`,
    });

    sdk = new NodeSDK({
      resource,
      traceExporter: exporter,
      instrumentations: [getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-fs': { enabled: false },
      })],
    });
    sdk.start();
  } catch (err) {
    // Optional dependency path for minimal installs / tests
    if (process.env.NODE_ENV !== 'test') {
      // eslint-disable-next-line no-console
      console.warn('[tracing] OpenTelemetry init skipped:', err.message);
    }
  }
}

function shutdownTracing() {
  if (!sdk) return;
  return sdk.shutdown().catch(() => {});
}

module.exports = { initTracing, shutdownTracing };
