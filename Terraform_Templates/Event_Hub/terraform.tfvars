resource_group_name      = "mypocportal"
location                 = "westus2"
event_hub_namespace_name = "poc-hubnamespace2022"
sku                      = "Basic"
throughput_units         = "1"

event_hub_details = [
  {
    eventhub_name                     = "hub01"
    eventhub_partition_count          = 2
    eventhub_message_retention_period = 2
  },

  {
    eventhub_name                     = "hub02"
    eventhub_partition_count          = 1
    eventhub_message_retention_period = 7
  }
]

