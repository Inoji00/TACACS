"""Short display names without changing the Compose project or its resources."""

SERVICE_NAMES = {'app': 'app', 'admin': 'admin', 'proxy': 'proxy', 'postgres': 'db'}


def names(project, *, primary):
    prefix = 'tnac' if primary else f'tnac-{project[-8:]}'
    return {service: f'{prefix}-{suffix}' for service, suffix in SERVICE_NAMES.items()}


def configure(config, project, *, primary):
    for service, name in names(project, primary=primary).items():
        config['services'][service]['container_name'] = name
    return config


def apply(directory, item, *, primary, run, compose, persist):
    desired = names(item['project'], primary=primary)
    occupied = set(run(['docker', 'ps', '-a', '--format', '{{.Names}}']).stdout.splitlines())
    planned = []
    for service, name in desired.items():
        containers = run(compose + ['ps', '-a', '-q', service]).stdout.splitlines()
        if len(containers) != 1:
            raise ValueError(f'Expected one container for {service}')
        container, = containers
        current = run(['docker', 'inspect', '--format', '{{.Name}}', container]).stdout.strip().lstrip('/')
        if current == name:
            continue
        if name in occupied:
            raise ValueError(f'Container name already in use: {name}')
        planned.append((container, name))
    for container, name in planned:
        run(['docker', 'rename', container, name])
    persist(directory, transform=lambda config: configure(config, item['project'], primary=primary))
