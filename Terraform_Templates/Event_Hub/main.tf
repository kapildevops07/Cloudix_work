resource "azurerm_eventhub_namespace" "paloalto_eventhub_namespace" {
  name                = var.event_hub_namespace_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.sku
  capacity            = var.throughput_units
}

resource "azurerm_eventhub" "paloalto_eventhub" {
  count               = length(var.event_hub_details)
  namespace_name      = azurerm_eventhub_namespace.paloalto_eventhub_namespace.name
  resource_group_name = var.resource_group_name
  name                = var.event_hub_details[count.index].eventhub_name
  partition_count     = var.event_hub_details[count.index].eventhub_partition_count
  message_retention   = var.sku == "Basic" ? 1 : var.event_hub_details[count.index].eventhub_message_retention_period
}