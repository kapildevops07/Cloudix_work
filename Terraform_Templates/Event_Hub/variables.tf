# Resource group 
variable "resource_group_name" {
  description = "The name of the resource group in which to create search service"
  default     = "mypocportal"
}

variable "location" {
  description = "The location/region where the search service is created."
  type        = string
}
#Event Hub Namespace
variable "event_hub_namespace_name" {
  description = "The name of event hub namespace"
  type        = string
}

variable "sku" {
  description = "The Name of the SKU used for this Key Vault. Possible values are `standard` and `premium`."
  default     = "Standard"
}

variable "throughput_units" {
  description = "Number of throughput units"
  type        = number
  default     = "1"
}

variable "event_hub_details" {
  description = "The variable holds the details of list of event hubs to provision."
  type = list(object({
    eventhub_name                     = string,
    eventhub_partition_count          = number, # Specifies the current number of shards on the Event Hub
    eventhub_message_retention_period = number, # Specifies the number of days to retain the events for this Event Hub
  }))
  default = []
}

variable "event_hub_consumergroup_info" {
  description = "This variable holds Event Hubs Consumer Group details"
  type = list(object({
    consumergroup_name     = string,
    eventhub_eventhub_name = string,
  }))
  default = []
}