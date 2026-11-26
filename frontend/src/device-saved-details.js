_ && z.jsxs("aside", {
  className: "device-saved-details",
  children: [
    z.jsx("h3", {children: o("Saved configuration")}),
    z.jsx("dl", {
      children: [
        [o("Status"), z.jsx("span", {className: "badge", children: o(_.enabled ? "Enabled" : "Disabled")})],
        [o("Device name"), _.name],
        [o("Source IPv4"), z.jsx("code", {children: _.address})],
        [o("Protocol support"), "TACACS+ · TCP/49"],
        [o("Location"), _.location_id ? Jt(c, _.location_id) || "—" : "—"],
        [o("Device Type"), _.device_type_id ? Jt(c, _.device_type_id) || "—" : "—"],
        [o("Saved at"), _.saved_at ? Rt(_.saved_at) : "—"],
      ].map(([label, value]) => z.jsxs("div", {
        children: [z.jsx("dt", {children: label}), z.jsx("dd", {children: value})],
      }, label)),
    }),
  ],
})
