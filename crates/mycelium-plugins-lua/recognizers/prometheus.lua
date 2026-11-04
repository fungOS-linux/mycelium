-- Passive recognizer for Prometheus-style metrics endpoints.
--
-- The recognizer is pure: it turns an advertisement into a stable device
-- fact. It observes an endpoint; it never probes it, never proves that the
-- endpoint answers, and never grants access to the scraped data. A lease
-- that expires is an expired lease.

recognizer = {
  name = "prometheus",

  recognize = function(advertisement)
    local services = {
      ["_prometheus._tcp"] = { kind = "metrics.server", model = "prometheus" },
      ["_node-exporter._tcp"] = { kind = "metrics.exporter", model = "node_exporter" },
    }
    local descriptor = services[advertisement.service_type]
    if descriptor == nil then
      return nil
    end

    local txt = advertisement.txt_map or {}
    local id = txt["id"] or txt["uuid"]
    if id == nil or id == "" then
      return nil
    end

    local path = txt["path"] or "/metrics"
    if string.match(path, "^/metrics[%w%._~/%-]*$") == nil
        or string.find(path, "..", 1, true) ~= nil then
      path = "/metrics"
    end

    local observed = {}
    if advertisement.port ~= nil then
      observed = {
        { name = "metrics", transport = "tcp", port = advertisement.port },
      }
    end

    return {
      stable_id = "prometheus:" .. string.lower(id),
      name = advertisement.instance,
      kind = descriptor.kind,
      vendor = "Prometheus",
      model = descriptor.model,
      serial = id,
      addresses = advertisement.addresses or {},
      attributes = {
        metrics_path = path,
        target = advertisement.target or "",
      },
      services = observed,
    }
  end,
}
