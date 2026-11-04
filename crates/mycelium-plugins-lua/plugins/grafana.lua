-- Grafana adapter.
--
-- The plugin is pure: it plans one bounded request to the local Grafana
-- health endpoint and parses the reply. Like every adapter in this
-- directory it uses the existing bounded command ABI, so it adds no HTTP
-- networking, credential access, or session handling to the Lua sandbox.
--
-- Only the unauthenticated loopback health endpoint is reachable: the host
-- is always 127.0.0.1, the scheme is always plain HTTP, and no userinfo,
-- query string, or fragment can be expressed. Grafana's own API keys,
-- cookies, and session state are never read, stored, or forwarded.

local MAX_BODY_BYTES = 65536

local function endpoint(params)
  params = params or {}
  local port = 3000
  if params.port ~= nil and params.port ~= "" then
    local value = tonumber(params.port)
    if value == nil or value ~= math.floor(value) or value < 1 or value > 65535 then
      return nil, "port must be an integer between 1 and 65535"
    end
    port = value
  end
  local path = params.path
  if path == nil or path == "" then path = "/api/health" end
  if type(path) ~= "string" or path ~= "/api/health" then
    return nil, "path must be /api/health, without query, fragment, or traversal"
  end
  return "http://127.0.0.1:" .. string.format("%d", port) .. path
end

local function health_command(url)
  return {
    program = "curl",
    args = { "--silent", "--show-error", "--max-time", "5", "--proto", "=http", url },
  }
end

local function trimmed(value)
  return (string.gsub(value or "", "^%s*(.-)%s*$", "%1"))
end

-- The health document is a small JSON object. The raw form is used for
-- recognition so a non-JSON answer is a recognition miss, not a host error.
local function looks_like_health(body)
  if type(body) ~= "string" then return false end
  return string.find(body, '"database"', 1, true) ~= nil
    and string.find(body, '"version"', 1, true) ~= nil
end

plugin = {
  name = "grafana",
  kind = "other",

  probe = function(target)
    local url = endpoint({})
    return { commands = { health_command(url) } }
  end,

  recognize = function(outputs, target)
    return looks_like_health(outputs[1])
  end,

  capabilities = function()
    return {
      { id = "system.identify", description = "Grafana health identity", mutation = false },
      {
        id = "grafana.health",
        description = "Grafana database and version health",
        mutation = false,
        optional = {
          { name = "port", ty = "string", docs = "local Grafana port (default 3000)" },
          { name = "path", ty = "string", docs = "health path (default /api/health)" },
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
          health_command(url),
          { program = "hostname" },
        },
        parse = "parse_identity",
      }
    elseif cap == "grafana.health" then
      local url, error = endpoint(params)
      if url == nil then return { ok = false, message = error } end
      return {
        commands = {
          {
            program = "curl",
            args = { "--silent", "--show-error", "--max-time", "5", "--proto", "=http", url },
            decode = "json",
          },
        },
        parse = "parse_health",
      }
    end
    return { ok = false, message = "unknown capability " .. cap }
  end,

  parse_identity = function(outputs, params)
    local body = outputs[1]
    if not looks_like_health(body) then
      return { ok = false, message = "the endpoint did not return a Grafana health document" }
    end
    local version = string.match(body, '"version"%s*:%s*"([^"]*)"')
    local hostname = trimmed(outputs[2])
    if hostname == "" then
      return { ok = false, message = "the target did not report a hostname" }
    end
    return {
      result = {
        vendor = "Grafana",
        model = "grafana",
        firmware = version,
        hostname = hostname,
        stable_id = hostname,
      },
    }
  end,

  parse_health = function(outputs, params)
    local document = outputs[1]
    if type(document) ~= "table" then
      return { ok = false, message = "the health endpoint returned an unexpected document" }
    end
    local database = document.database
    local version = document.version
    if type(database) ~= "string" or type(version) ~= "string" then
      return { ok = false, message = "the health endpoint returned an unexpected document" }
    end
    return {
      result = {
        database = database,
        version = version,
        healthy = database == "ok",
      },
    }
  end,
}
