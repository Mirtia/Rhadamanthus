struct StateTask {
  const char task_name[50];
   int (*init)(vmi_instance_t);
    int (*execute)(vmi_instance_t);
    void (*cleanup)(void);
};