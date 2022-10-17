
set( FILE_LIST
    mqtt.cc
    mqtt.h
    mqtt_paf.cc
    mqtt_paf.h
    mqtt_module.cc
    mqtt_module.h
    mqtt_message.cc
    mqtt_message.h
    mqtt_config.h
    mqtt_utils.h
    ips_mqtt.cc
    ips_mqtt_type
)

if (STATIC_INSPECTORS)
    add_library( mqtt OBJECT ${FILE_LIST})

else (STATIC_INSPECTORS)
    add_dynamic_module(mqtt inspectors ${FILE_LIST})

endif (STATIC_INSPECTORS)

