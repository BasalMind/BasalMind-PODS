// Plain, short US English labels for the pod panel. Keys follow schema/facets.
export const LABELS = {
  health: {
    title: "Health notes",
    lists: {
      allergies: {
        title: "Allergies",
        add_label: "Add an allergy",
        fields: { substance: "Allergic to", reaction: "Reaction", severity: "Severity" },
      },
      medications: {
        title: "Medications",
        add_label: "Add a medication",
        fields: { name: "Medication", dose: "Dose", when: "When I take it" },
      },
      history: {
        title: "Health history",
        add_label: "Add to my history",
        fields: { what: "What", when: "When", note: "Note" },
      },
      providers: {
        title: "My providers",
        add_label: "Add a provider",
        fields: { role: "Type", name: "Name", contact: "Phone or email", next_visit: "Next visit", notes: "Notes" },
      },
      insurance: {
        title: "Insurance",
        add_label: "Add a plan",
        fields: { plan_name: "Plan name", renewal_date: "Renewal date", notes: "Notes" },
      },
    },
  },
};
