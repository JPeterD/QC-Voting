"""
Tracing utility using OpenTelemetry
"""

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
import os
from functools import wraps
from opentelemetry.exporter.jaeger.thrift import JaegerExporter

# Initialize tracer provider with service name
resource = Resource.create({"service.name": "quantum-voting-app"})
tracer_provider = TracerProvider(resource=resource)
trace.set_tracer_provider(tracer_provider)

# Add console exporter for development
tracer_provider.add_span_processor(
    BatchSpanProcessor(ConsoleSpanExporter())
)

# OTLP exporter for production use (if configured)
otlp_endpoint = os.environ.get("OTLP_ENDPOINT")
if otlp_endpoint:
    otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(otlp_exporter)
    )
# Jaeger exporter (if configured)
jaeger_host = os.environ.get("JAEGER_HOST", "localhost")
jaeger_port = int(os.environ.get("JAEGER_PORT", "6831"))
enable_jaeger = os.environ.get("ENABLE_JAEGER", "false").lower() == "true"

if enable_jaeger:
    jaeger_exporter = JaegerExporter(
        agent_host_name=jaeger_host,
        agent_port=jaeger_port,
    )
    tracer_provider.add_span_processor(
        BatchSpanProcessor(jaeger_exporter)
    )

# Get a tracer
tracer = trace.get_tracer("quantum-voting.tracer")

# Additional tracer provider for backend operations with a different service name
backend_resource = Resource.create({"service.name": "quantum-voting-backend"})
backend_tracer_provider = TracerProvider(resource=backend_resource)

# Use same exporters for backend tracer
backend_tracer_provider.add_span_processor(
    BatchSpanProcessor(ConsoleSpanExporter())
)

if otlp_endpoint:
    backend_tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint))
    )

if enable_jaeger:
    backend_tracer_provider.add_span_processor(
        BatchSpanProcessor(JaegerExporter(
            agent_host_name=jaeger_host,
            agent_port=jaeger_port,
        ))
    )

backend_tracer = backend_tracer_provider.get_tracer("quantum-voting.backend.tracer")

def instrument_flask_app(app):
    """
    Instrument a Flask application with OpenTelemetry
    """
    FlaskInstrumentor().instrument_app(app)
    return app

def trace_function(name=None):
    """
    Decorator to trace a function
    
    Args:
        name (str, optional): Name for the span. If not provided, function name is used.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            span_name = name or func.__name__
            with tracer.start_as_current_span(span_name):
                return func(*args, **kwargs)
        return wrapper
    return decorator

def trace_method(name=None):
    """
    Decorator to trace a class method
    
    Args:
        name (str, optional): Name for the span. If not provided, method name is used.
    """
    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            span_name = name or f"{self.__class__.__name__}.{method.__name__}"
            with tracer.start_as_current_span(span_name):
                return method(self, *args, **kwargs)
        return wrapper
    return decorator