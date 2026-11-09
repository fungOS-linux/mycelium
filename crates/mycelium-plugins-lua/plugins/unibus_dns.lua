-- Optional naming policy. No peer selection, addresses, DNS I/O or authority.
-- Unibus already supplies generic application-owned leases; do not scrape it.
dns_policy = {
  aliases = function(context)
    return { ["unibus-viewer"] = "unibus" }
  end,
}
