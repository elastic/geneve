from geneve_pipes.generate import PreparedRule, destination_for, event_categories


def test_event_categories_accepts_strings_and_lists():
    assert event_categories({"event": {"category": "process"}}) == ("process",)
    assert event_categories({"event": {"category": ["process", "file"]}}) == ["process", "file"]


def test_destination_uses_matching_rule_index_pattern():
    rule = PreparedRule("rule-id", object(), ["logs-endpoint.events.process-*"])
    destinations = {
        "file": "logs-endpoint.events.file-default",
        "process": "logs-endpoint.events.process-default",
    }

    assert destination_for({"event": {"category": "process"}}, rule, destinations) == "logs-endpoint.events.process-default"
    assert destination_for({"event": {"category": "file"}}, rule, destinations) is None
