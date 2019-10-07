#!/usr/bin/env python
# coding=utf-8


__author__  = "matt.pinizzotto@wwt.com"

import copy

def get_edge(client_session, edge_name):
    all_edge = client_session.read_all_pages('nsxEdges', 'read')

    try:
        edge_params = [scope for scope in all_edge if scope['name'] == edge_name][0]
        edge_id = edge_params['objectId']
    except IndexError:
        return None, None

    return edge_id, edge_params


def check_bgp_state(current_config):
    if 'bgp' in current_config['routing']:
        if current_config['routing']['bgp']['enabled'] == 'true':
            return True
        else:
            return False
    else:
        return False


def set_bgp_state(resource_body):
    resource_body['bgp']['enabled'] = 'true'
    return True, resource_body


def check_bgp_as(current_config, resource_body, localASNumber):
    changed = False

    if 'bgp' in current_config['routing']:
        current_bgp = current_config['routing']['bgp']
        c_localASNumber = current_bgp.get('localASNumber')

        if c_localASNumber != localASNumber:
            resource_body['bgp']['localASNumber'] = localASNumber
            changed = True
            return changed, resource_body

        else:
            resource_body['bgp']['localASNumber'] = c_localASNumber
            changed = False
            return changed, resource_body

    else:
        resource_body['bgp']['localASNumber'] = localASNumber
        changed = True

        return changed, resource_body


def check_router_id(current_config, router_id):
    current_routing_cfg = current_config['routing']['routingGlobalConfig']
    current_router_id = current_routing_cfg.get('routerId', None)

    if current_router_id == router_id:
        return False, current_config
    else:
        current_config['routing']['routingGlobalConfig']['routerId'] = router_id
        return True, current_config


def check_ecmp(current_config, ecmp):
    current_ecmp_cfg = current_config['routing']['routingGlobalConfig']
    current_ecmp_state = current_ecmp_cfg.get('ecmp', None)

    if current_ecmp_state == ecmp:
        return False, current_config
    else:
        current_config['routing']['routingGlobalConfig']['ecmp'] = ecmp
        return True, current_config


def check_bgp_options(current_config, resource_body, graceful_restart, default_originate):
    changed = False

    if 'bgp' in current_config['routing']:
        current_bgp = current_config['routing']['bgp']
        c_grst_str = current_bgp.get('gracefulRestart', 'false')
        c_dio_str = current_bgp.get('defaultOriginate', 'false')

        if c_grst_str == 'true':
            c_grst = True
        else:
            c_grst = False

        if c_dio_str == 'true':
            c_dio = True
        else:
            c_dio = False

        if c_grst != graceful_restart and graceful_restart:
            resource_body['bgp']['gracefulRestart'] = 'true'
            changed = True
        elif c_grst != graceful_restart and not graceful_restart:
            resource_body['bgp']['gracefulRestart'] = 'false'
            changed = True
        elif c_grst == graceful_restart and not graceful_restart:
            resource_body['bgp']['gracefulRestart'] = 'false'
            changed = False
        else:
            resource_body['bgp']['gracefulRestart'] = 'true'
            changed = False

        if c_dio != default_originate and default_originate:
            resource_body['bgp']['defaultOriginate'] = 'true'
            changed = True
        elif c_dio != default_originate and not default_originate:
            resource_body['bgp']['defaultOriginate'] = 'false'
            changed = True

        return changed, resource_body

    else:
        resource_body['bgp']['gracefulRestart'] = graceful_restart
        resource_body['bgp']['defaultOriginate'] = default_originate
        changed = True

        return changed, resource_body


def normalize_neighbour_list(neighbour_list, localASNumber):
    new_neighbour_list = []

    if neighbour_list:
        for neighbour in neighbour_list:

            if not isinstance(neighbour, dict):
                return False, 'Neighbour_list {} is not a valid dictionary'.format(neighbour)

            if neighbour.get('ipAddress', 'missing') == 'missing':
                return False, 'Neighbour list entry {} in your list is missing the mandatory ipAddress parameter'.format(
                    neighbour.get('ipAddress', None))
            else:
                neighbour['ipAddress'] = str(neighbour['ipAddress'])

            if neighbour.get('remoteASNumber', 'missing') == 'missing':
                return False, 'Neighbour list entry {} in your list is missing the mandatory remoteASNumber parameter'.format(
                    neighbour.get('remoteASNumber', None))
            else:
                neighbour['remoteASNumber'] = str(neighbour['remoteASNumber'])

            if neighbour.get('bgpFilters', 'missing') == 'missing':
                neighbour['bgpFilters'] = None

            else:
                neighbour['holdDownTimer'] = str(neighbour['holdDownTimer'])

            if neighbour.get('holdDownTimer', 'missing') == 'missing':
                neighbour['holdDownTimer'] = '180'
            else:
                neighbour['holdDownTimer'] = str(neighbour['holdDownTimer'])

            if neighbour.get('weight', 'missing') == 'missing':
                neighbour['weight'] = '60'

            else:
                neighbour['weight'] = str(neighbour['weight'])

            #remove 'removePrivateAS' from neighbour list if iBGP
            if localASNumber != neighbour.get('remoteASNumber'):
                if neighbour.get('removePrivateAS', 'missing') == 'missing':
                    neighbour['removePrivateAS'] = 'false'

                else:
                    neighbour['removePrivateAS'] = str(neighbour['removePrivateAS'])
            else:
                pass

            if neighbour.get('remoteASNumber', 'missing') == 'missing':
                neighbour['remoteASNumber'] = neighbour['remoteASNumber']

            else:
                neighbour['remoteASNumber'] = str(neighbour['remoteASNumber'])

            if neighbour.get('keepAliveTimer', 'missing') == 'missing':
                neighbour['keepAliveTimer'] = '60'

            else:
                neighbour['keepAliveTimer'] = str(neighbour['keepAliveTimer'])

            if neighbour.get('password', 'missing') == 'missing':
                return False, 'Neighbour list entry {} in your list is missing the mandatory password parameter'.format(
                    neighbour.get('password', None))

            else:
                neighbour['password'] = str(neighbour['password'])


            new_neighbour_list.append(neighbour)

    return True, None, new_neighbour_list

def compare_without_password(input_bgp_neighbours, api_neighbour_list): # Take two lists of dictionaries and compare them excluding password key as this is encrytped from API
    changed = False
    
    d1pass = False
    d2pass = False

    for d1 in input_bgp_neighbours:
        for key, value in d1.items():
            if key == 'password':
                d1.pop(key)
                d1pass = True

    for d2 in api_neighbour_list:
        for key, value in d2.items():
            if key == 'password':
                d2.pop(key)
                d2pass = True

    for items in input_bgp_neighbours:
        if not items in api_neighbour_list:
            changed = True

    if (d1pass and d2pass) or (not d1pass and not d2pass): # Check if MD5 password was added or removed
        passchange = False
    else:
        passchange = True

    return changed

def check_bgp_neighbours(client_session, current_config, resource_body, bgp_neighbours, add_nbr_overload):
    changed = False
    n_neighbour_list = []

    if 'bgp' in current_config['routing']:

        if current_config['routing']['bgp']['bgpNeighbours']:
            c_neighbour_list = client_session.normalize_list_return(
                current_config['routing']['bgp']['bgpNeighbours']['bgpNeighbour'])

        else:
            c_neighbour_list = []

        pop_bgp_neighbours =  copy.deepcopy(bgp_neighbours)
        pop_c_neighbour_list =  copy.deepcopy(c_neighbour_list)      

        if compare_without_password(pop_bgp_neighbours,pop_c_neighbour_list) or add_nbr_overload:
            for items in bgp_neighbours:
                if not items in c_neighbour_list:
                    n_neighbour_list.append(items)
                    changed = True

        resource_body['bgp']['bgpNeighbours'] = {'bgpNeighbour': n_neighbour_list}
        
        return changed, current_config, resource_body

    else:
        c_neighbour_list = []
        for new_neighbour in bgp_neighbours:
            c_neighbour_list.append(new_neighbour)

        resource_body['bgp']['bgpNeighbours'] = {'bgpNeighbour': c_neighbour_list}
        changed = True

        return changed, current_config, resource_body


def get_current_config(client_session, edge_id):
    response = client_session.read('routingConfig', uri_parameters={'edgeId': edge_id})
    return response['body']


def get_resource_body(client_session):
    response = client_session.extract_resource_body_example('routingBGP', 'update')
    return response


def update_config(client_session, current_config, edge_id):
    client_session.update('routingConfig', uri_parameters={'edgeId': edge_id},
                          request_body_dict=current_config)


def update_config_bgp(client_session, resource_body, edge_id):
    client_session.update('routingBGP', uri_parameters={'edgeId': edge_id}, request_body_dict=resource_body)


def reset_config(client_session, edge_id):
    client_session.delete('routingConfig', uri_parameters={'edgeId': edge_id})


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent']),
            nsxmanager_spec=dict(required=True, no_log=True, type='dict'),
            edge_name=dict(required=True, type='str'),
            graceful_restart=dict(default=False, type='bool'),
            default_originate=dict(default=False, type='bool'),
            router_id=dict(required=True, type='str'),
            ecmp=dict(default='false', choices=['true', 'false']),
            localASNumber=dict(required=True, type='str'),
            bgp_neighbours=dict(required=True, type='list')
        ),
        supports_check_mode=False
    )

    changed_state=False
    add_nbr_overload=False

    from nsxramlclient.client import NsxClient

    client_session = NsxClient(module.params['nsxmanager_spec']['raml_file'], module.params['nsxmanager_spec']['host'],
                               module.params['nsxmanager_spec']['user'], module.params['nsxmanager_spec']['password'])

    edge_id, edge_params = get_edge(client_session, module.params['edge_name'])
    if not edge_id:
        module.fail_json(msg='could not find Edge with name {}'.format(module.params['edge_name']))

    current_config = get_current_config(client_session, edge_id)
    resource_body = get_resource_body(client_session)

    if module.params['state'] == 'absent' and check_bgp_state(current_config):
        reset_config(client_session, edge_id)
        module.exit_json(changed=True, current_config=None)

    elif module.params['state'] == 'absent' and not check_bgp_state(current_config):
        module.exit_json(changed=False, current_config=None)

    elif module.params['state'] == 'present' and not check_bgp_state(current_config):
        changed_state, resource_body = set_bgp_state(resource_body)

    changed_as, resource_body = check_bgp_as(current_config, resource_body, module.params['localASNumber'])
    changed_opt, resource_body = check_bgp_options(current_config, resource_body, module.params['graceful_restart'],
                                                   module.params['default_originate'])

    changed_rtid, current_config = check_router_id(current_config, module.params['router_id'])
    changed_ecmp, current_config = check_ecmp(current_config, module.params['ecmp'])

    valid, msg, neighbour_list = normalize_neighbour_list(module.params['bgp_neighbours'], module.params['localASNumber'])
    if not valid:
        module.fail_json(msg=msg)

    if  (changed_state or changed_as or changed_opt):
        add_nbr_overload = True

    changed_neighbours, current_config, resource_body = check_bgp_neighbours(client_session, current_config,
                                                                             resource_body, neighbour_list,add_nbr_overload)

    if  (changed_rtid or changed_ecmp):
        update_config(client_session, current_config, edge_id)
        module.exit_json(changed=True, current_config=current_config, resource_body=resource_body)

    if  (changed_neighbours or changed_state or changed_as or changed_opt):
        update_config_bgp(client_session, resource_body, edge_id)
        
        module.exit_json(changed=True, current_config=current_config, resource_body=resource_body)        
    else:
        module.exit_json(changed=False, current_config=current_config, resource_body=resource_body)


from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()