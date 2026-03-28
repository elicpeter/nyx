from input_reader import get_raw_input


def prepare_command(extra_args=""):
    """PASSTHROUGH wrapper: calls the source function and returns the result
    (with an optional suffix appended).

    Taint propagates through this layer without any sanitisation.
    This is the second hop of the three-file chain.
    """
    raw = get_raw_input()
    return (raw + " " + extra_args) if extra_args else raw
