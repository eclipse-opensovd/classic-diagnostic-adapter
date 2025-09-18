from odxtools.diaglayercontainer import DiagLayerContainer
from odxtools.diaglayers.diaglayerraw import DiagLayerRaw
from odxtools.functionalclass import FunctionalClass
from odxtools.statetransition import StateTransition


def find_state_transition(container: DiagLayerRaw | DiagLayerContainer, name: str) -> StateTransition:
    if isinstance(container, DiagLayerRaw):
        for state_chart in container.state_charts.values():
            for state_transition in state_chart.state_transitions:
                if state_transition.short_name == name:
                    return state_transition

    if isinstance(container, DiagLayerContainer):
        for base_variant in container.base_variants.values():
            res = find_state_transition(base_variant.base_variant_raw, name)
            if res is not None:
                return res
        for ecu_variant in container.ecu_variants.values():
            res = find_state_transition(ecu_variant.ecu_variant_raw, name)
            if res is not None:
                return res

    raise Exception(f"No state transition found {name}")

def find_functional_class(container: DiagLayerRaw | DiagLayerContainer, name: str) -> FunctionalClass:
    if isinstance(container, DiagLayerRaw):
        res = container.functional_classes[name]
        if res is not None:
            return res

    if isinstance(container, DiagLayerContainer):
        for base_variant in container.base_variants.values():
            res = find_functional_class(base_variant.base_variant_raw, name)
            if res is not None:
                return res
        for ecu_variant in container.ecu_variants.values():
            res = find_functional_class(ecu_variant.ecu_variant_raw, name)
            if res is not None:
                return res

    raise Exception(f"No functional class found {name}")
