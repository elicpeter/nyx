from executor import prepare_and_run

def transform_input(data):
    processed = data.strip()
    prepare_and_run(processed)
    return processed
