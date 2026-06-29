pub struct Subscription<'a> {
    pub id: &'a str,
    pub name: &'a str,
}

pub static GAMEPASS_SUBS: &[Subscription] = &[
    Subscription {
        id: "CFQ7TTC0K5DJ",
        name: "Xbox Game Pass Essential",
    },
    Subscription {
        id: "CFQ7TTC0P85B",
        name: "Xbox Game Pass Premium",
    },
    Subscription {
        id: "CFQ7TTC0KHS0",
        name: "Xbox Game Pass Ultimate",
    },
    Subscription {
        id: "CFQ7TTC0KGQ8",
        name: "PC Game Pass",
    },
    // Legacy Xbox console sub
    Subscription {
        id: "CFQ7TTC0K6L8",
        name: "Xbox Game Pass for Console",
    },
];
