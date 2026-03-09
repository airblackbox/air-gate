"""
Optional OpenTelemetry tracing for AIR Blackbox Gate.

If the OTEL packages are installed, tracing is auto-configured.
If not, all tracing calls are no-ops — zero impact on the app.

This gives Jaeger integration for free when running via Docker Compose.
"""

import logging
import os

logger = logging.getLogger("gate.tracing")

# Sentinel for "tracing not available"
_tracer = None
_enabled = False


def setup_tracing(app=None):
    """
    Initialize OpenTelemetry tracing if packages are available.
    Call this at startup. Safe to call even without OTEL installed.
    """
    global _tracer, _enabled

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource

        # Only enable if endpoint is configured
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
        if not endpoint:
            logger.info("OTEL_EXPORTER_OTLP_ENDPOINT not set — tracing disabled")
            return

        service_name = os.getenv("OTEL_SERVICE_NAME", "air-blackbox-gate")

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        _tracer = trace.get_tracer("gate")
        _enabled = True

        # Instrument FastAPI if available
        if app:
            try:
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
                FastAPIInstrumentor.instrument_app(app)
                logger.info(f"Tracing enabled → {endpoint} (FastAPI instrumented)")
            except ImportError:
                logger.info(f"Tracing enabled → {endpoint} (FastAPI instrumentation not available)")

        logger.info(f"OpenTelemetry tracing initialized: {service_name} → {endpoint}")

    except ImportError:
        logger.info("OpenTelemetry not installed — tracing disabled (pip install opentelemetry-api opentelemetry-sdk)")
    except Exception as e:
        logger.warning(f"Failed to initialize tracing: {e}")


def get_tracer():
    """Get the tracer instance (or None if tracing is disabled)."""
    return _tracer


def is_enabled():
    """Check if tracing is active."""
    return _enabled
