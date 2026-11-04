-- Prometheus adapter.
--
-- The plugin is pure: it plans one bounded scrape of a loopback Prometheus
-- exposition endpoint and parses the reply. It never handles credentials:
-- the host is always 127.0.0.1, the scheme is always plain HTTP, and no
-- userinfo, query string, or fragment can be expressed. A successful scrape
-- proves that a metrics endpoint answered; it grants no access to the
-- Prometheus API, to the scraped targets, or to anything else on the host.
--
-- The scrape needs `curl` and `head` on the target. The window is bounded by
-- the host (1 MiB) and by the plugin, so a huge exposition is reported as a
-- bounded sample instead of being buffered without limit.

local MAX_PREFIX_BYTES = 4096
local MAX_BODY_BYTES = 1048576
local MAX_NAMES = 32
local MAX_NAME_BYTES = 128
local MAX_TARGETS = 256
local MAX_LABEL_BYTES = 256

-- The status marker keeps the HTTP status distinguishable from a sample
-- value that happens to look like one.
local STATUS_MARKER = "#mycelium-http-status:"
local SCRAPE = 'curl --silent --show-error --max-time 5 --proto "=http" --write-out "\\n#mycelium-http-status:%{http_code}" "$1"'

-- Only a loopback HTTP endpoint can be expressed. There is no way to point
-- this adapter at another host or to add credentials.
local function valid_path(path)
  if string.match(path, "^/metrics[%w%._~/%-]*$") ~= nil
      and string.find(path, "..", 1, true) == nil then
    return true
  end
  return path == "/api/v1/targets"
end

local function endpoint(params, kind)
  params = params or {}
  local port = 9090
  if params.port ~= nil and params.port ~= "" then
    local value = tonumber(params.port)
    if value == nil or value ~= math.floor(value) or value < 1 or value > 65535 then
      return nil, "port must be an integer between 1 and 65535"
    end
    port = value
  end
  local path = params.path
  if path == nil or path == "" then
    path = (kind == "targets") and "/api/v1/targets" or "/metrics"
  end
  if type(path) ~= "string" or not valid_path(path) then
    return nil, "path must be a /metrics path or /api/v1/targets, without query, fragment, or traversal"
  end
  return "http://127.0.0.1:" .. string.format("%d", port) .. path
end

local function scrape(url, limit)
  return {
    program = "sh",
    args = { "-c", SCRAPE .. " | head -c " .. string.format("%d", limit), "sh", url },
  }
end

-- Split a label block, honouring quoted values so a `}` inside a label
-- value does not end the block early.
local function split_labels(rest)
  local index = 2
  local quoted = false
  local escaped = false
  while index <= #rest do
    local character = string.sub(rest, index, index)
    if quoted then
      if escaped then
        escaped = false
      elseif character == "\\" then
        escaped = true
      elseif character == '"' then
        quoted = false
      end
    elseif character == '"' then
      quoted = true
    elseif character == "}" then
      return string.sub(rest, 2, index - 1), string.sub(rest, index + 1)
    end
    index = index + 1
  end
  return nil, nil
end

local function label_value(labels, key)
  local needle = key .. "="
  local from = 1
  while true do
    local start, stop = string.find(labels, needle, from, true)
    if start == nil then return nil end
    local before = string.sub(labels, start - 1, start - 1)
    if before == "" or before == "," or before == " " or before == "{" then
      local value = string.match(string.sub(labels, stop + 1), '^"([^"]*)"')
      if value ~= nil then return value end
    end
    from = stop + 1
  end
end

-- The sample value: a float, or one of the special float spellings. Lua
-- patterns have no alternation, so each shape is checked on its own.
local function value_of(rest)
  local token = string.match(rest, "^%s*([^%s]+)")
  if token == nil then return nil end
  if token == "NaN" or token == "+Inf" or token == "-Inf" then return token end
  if string.match(token, "^[%-+]?%d+%.?%d*[eE]?[%-+]?%d*$") == nil then return nil end
  return token
end

-- One exposition sample: name, labels, and value.
local function sample(line)
  local name, rest = string.match(line, "^([%a_:][%w_:]*)%s*(.*)$")
  if name == nil then return nil end
  local labels = ""
  if string.sub(rest, 1, 1) == "{" then
    local block, tail = split_labels(rest)
    if block == nil then return nil end
    labels = block
    rest = tail
  end
  local value = value_of(rest)
  if value == nil then return nil end
  return name, labels, value
end

-- Parse a Prometheus text exposition (0.0.4 or OpenMetrics) into a bounded
-- summary. Returns nil plus a message when the body is not an exposition.
local function parse_exposition(text)
  if text == nil or text == "" then
    return nil, "the metrics endpoint returned an empty body"
  end
  local status = nil
  local marker = string.find(text, STATUS_MARKER, 1, true)
  if marker ~= nil then
    local code = string.match(string.sub(text, marker + #STATUS_MARKER), "^(%d+)%s*$")
    if code ~= nil then status = code end
    text = string.sub(text, 1, marker - 1)
  end
  if status ~= nil and status ~= "200" then
    return nil, "the metrics endpoint returned HTTP " .. status
  end
  if text == "" then
    return nil, "the metrics endpoint returned an empty body"
  end
  local head = string.lower(string.sub(text, 1, 256))
  if string.find(head, "<!doctype html", 1, true) or string.find(head, "<html", 1, true) then
    return nil, "the metrics endpoint returned HTML, not a Prometheus exposition"
  end
  if string.find(head, "404 page not found", 1, true) then
    return nil, "the metrics endpoint returned HTTP 404"
  end
  local names = {}
  local seen = {}
  local families = 0
  local samples = 0
  local up = nil
  local duration = nil
  local version = nil
  local model = nil
  local lines = 0
  for line in string.gmatch(text .. "\n", "([^\n]*)\n") do
    if line ~= "" then
      lines = lines + 1
      if string.sub(line, 1, 1) ~= "#" then
        local name, labels, value = sample(line)
        if name == nil then
          return nil, "the metrics endpoint returned a line that is not a Prometheus sample"
        end
        samples = samples + 1
        if not seen[name] then
          seen[name] = true
          families = families + 1
          if #names < MAX_NAMES and #name <= MAX_NAME_BYTES then
            names[#names + 1] = name
          end
        end
        if name == "up" and up == nil then up = value end
        if name == "scrape_duration_seconds" and duration == nil then duration = value end
        if name == "prometheus_build_info" and version == nil then
          version = label_value(labels, "version")
          model = "prometheus"
        end
        if name == "node_exporter_build_info" and model == nil then
          model = "node_exporter"
          if version == nil then version = label_value(labels, "version") end
        end
      end
    end
  end
  if samples == 0 then
    return nil, "the metrics endpoint returned no Prometheus samples"
  end
  return {
    families = families,
    samples = samples,
    lines = lines,
    up = up,
    scrape_duration_seconds = duration,
    version = version,
    model = model or "prometheus-compatible",
    names = names,
  }
end

local function trimmed(value)
  return (string.gsub(value or "", "^%s*(.-)%s*$", "%1"))
end

plugin = {
  name = "prometheus",
  kind = "other",

  -- Cheap, bounded probe: the first bytes of the exposition are enough to
  -- tell a metrics endpoint from any other HTTP service.
  probe = function(target)
    local url = endpoint({})
    return { commands = { scrape(url, MAX_PREFIX_BYTES) } }
  end,

  recognize = function(outputs, target)
    local summary = parse_exposition(outputs[1])
    return summary ~= nil
  end,

  capabilities = function()
    return {
      { id = "system.identify", description = "Prometheus exposition identity", mutation = false },
      {
        id = "prometheus.metrics",
        description = "bounded summary of the Prometheus exposition",
        mutation = false,
        optional = {
          { name = "port", ty = "string", docs = "local metrics port (default 9090)" },
          { name = "path", ty = "string", docs = "metrics path (default /metrics)" },
        },
      },
      {
        id = "prometheus.targets",
        description = "scrape target inventory (job, instance, health only)",
        mutation = false,
        optional = {
          { name = "port", ty = "string", docs = "local metrics port (default 9090)" },
          { name = "path", ty = "string", docs = "targets path (default /api/v1/targets)" },
        },
      },
    }
  end,

  exec = function(cap, params, ctx)
    if cap == "system.identify" then
      local url, error = endpoint(params)
      if url == nil then return { ok = false, message = error } end
      return {
        commands = {
          scrape(url, MAX_PREFIX_BYTES),
          { program = "hostname" },
        },
        parse = "parse_identity",
      }
    elseif cap == "prometheus.metrics" then
      local url, error = endpoint(params)
      if url == nil then return { ok = false, message = error } end
      return {
        commands = { scrape(url, MAX_BODY_BYTES) },
        parse = "parse_metrics",
      }
    elseif cap == "prometheus.targets" then
      local url, error = endpoint(params, "targets")
      if url == nil then return { ok = false, message = error } end
      return {
        commands = {
          {
            program = "curl",
            args = { "--silent", "--show-error", "--max-time", "5", "--proto", "=http", url },
            decode = "json",
          },
        },
        parse = "parse_targets",
      }
    end
    return { ok = false, message = "unknown capability " .. cap }
  end,

  parse_identity = function(outputs, params)
    local summary, error = parse_exposition(outputs[1])
    if summary == nil then
      return { ok = false, message = error }
    end
    local hostname = trimmed(outputs[2])
    if hostname == "" then
      return { ok = false, message = "the target did not report a hostname" }
    end
    return {
      result = {
        vendor = "Prometheus",
        model = summary.model,
        firmware = summary.version,
        hostname = hostname,
        stable_id = hostname,
      },
    }
  end,

  parse_metrics = function(outputs, params)
    local summary, error = parse_exposition(outputs[1])
    if summary == nil then
      return { ok = false, message = error }
    end
    return {
      result = {
        families = summary.families,
        samples = summary.samples,
        lines = summary.lines,
        up = summary.up,
        scrape_duration_seconds = summary.scrape_duration_seconds,
        version = summary.version,
        model = summary.model,
        families_sample = summary.names,
      },
    }
  end,

  -- The target inventory is projected to job, instance, and health. Scrape
  -- URLs and last-error strings are dropped: a configured target may embed
  -- credentials, and this adapter never carries them.
  parse_targets = function(outputs, params)
    local document = outputs[1]
    if type(document) ~= "table" or type(document.data) ~= "table" then
      return { ok = false, message = "the targets endpoint returned an unexpected document" }
    end
    local active = document.data.activeTargets
    if type(active) ~= "table" then
      return { ok = false, message = "the targets endpoint returned no target list" }
    end
    local targets = {}
    local total = 0
    local healthy = 0
    for _, target in ipairs(active) do
      total = total + 1
      if type(target) == "table" and #targets < MAX_TARGETS then
        local labels = type(target.labels) == "table" and target.labels or {}
        local job = labels.job
        local instance = labels.instance
        local health = target.health
        local row = {}
        if type(job) == "string" and #job <= MAX_LABEL_BYTES then row.job = job end
        if type(instance) == "string" and #instance <= MAX_LABEL_BYTES then row.instance = instance end
        if type(health) == "string" and #health <= MAX_LABEL_BYTES then row.health = health end
        if health == "up" then healthy = healthy + 1 end
        targets[#targets + 1] = row
      end
    end
    return {
      result = {
        active = total,
        healthy = healthy,
        projected = #targets,
        targets = targets,
      },
    }
  end,
}
