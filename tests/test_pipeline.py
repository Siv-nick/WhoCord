"""Tests for Stage/Pipeline execution order."""
from discord_osint.pipeline.base import Stage, Pipeline
from discord_osint.pipeline.context import InvestigationContext

class MockStage(Stage):
    name = "mock"
    def run(self, ctx, emit=None):
        ctx.results.setdefault(self.name, []).append("executed")

def test_pipeline_order():
    ctx = InvestigationContext(target_id=123, config=None, seed_type="manual", seed_value="test")
    stage1 = MockStage(); stage1.name = "stage1"
    stage2 = MockStage(); stage2.name = "stage2"
    pipeline = Pipeline([stage1, stage2], ctx)
    pipeline.run()
    assert ctx.results == {"stage1": ["executed"], "stage2": ["executed"]}