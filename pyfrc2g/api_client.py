"""
API client module for pfSense and OPNSense
"""

import requests
import urllib3
import logging
import traceback
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError
from pyfrc2g.utils import extract_base_url, update_api_maps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIClient:
    """API client for firewall gateways"""
    
    def __init__(self, config):
        self.config = config
        self.interface_map = {}
        self.net_map = {}
        self.address_map = {}
        self.port_map = {}
        self.alias_details = {}  # Store full alias details: {alias_name: {type, content, description}}
    
    def _handle_api_error(self, operation, url, error, log_level=logging.WARNING):
        """
        Centralized error handling for API requests.
        
        Args:
            operation: Description of the operation (e.g., "fetch aliases")
            url: The URL that was requested
            error: The exception that occurred
            log_level: Logging level to use (default: WARNING)
        """
        error_type = type(error).__name__
        
        if isinstance(error, Timeout):
            logging.log(log_level, f"Timeout while {operation} from {url}: {error}")
            logging.debug(f"Timeout details: {error}")
        elif isinstance(error, ConnectionError):
            logging.log(log_level, f"Connection error while {operation} from {url}: {error}")
            logging.debug(f"Connection error details: {error}")
        elif isinstance(error, HTTPError):
            logging.log(log_level, f"HTTP error while {operation} from {url}: {error}")
            if hasattr(error.response, 'status_code'):
                status = error.response.status_code
                if status == 401:
                    logging.error("Authentication failed. Check your API credentials (token/key/secret).")
                elif status == 403:
                    logging.error("Access forbidden. Check API user permissions.")
                elif status == 404:
                    logging.error(f"Endpoint not found: {url}. Check API URL configuration.")
                elif status >= 500:
                    logging.error(f"Server error (HTTP {status}). The firewall API may be unavailable.")
        elif isinstance(error, requests.exceptions.JSONDecodeError):
            logging.log(log_level, f"Invalid JSON response while {operation} from {url}: {error}")
            logging.debug(f"Response text (first 500 chars): {getattr(error, 'response', {}).text[:500] if hasattr(error, 'response') else 'N/A'}")
        elif isinstance(error, ValueError):
            logging.log(log_level, f"Value error while {operation}: {error}")
        else:
            logging.log(log_level, f"Unexpected error ({error_type}) while {operation} from {url}: {error}")
        
        if log_level == logging.DEBUG or logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.debug(f"Full traceback:\n{traceback.format_exc()}")
    
    def _make_api_request(self, url, method="GET", headers=None, auth=None, params=None, timeout=10, operation="API request"):
        """
        Make an API request with proper error handling.
        
        Args:
            url: The URL to request
            method: HTTP method (default: GET)
            headers: Request headers
            auth: Authentication tuple (for OPNSense)
            params: Query parameters
            timeout: Request timeout in seconds
            operation: Description of the operation for error messages
            
        Returns:
            Response object if successful, None otherwise
        """
        try:
            kwargs = {
                "verify": False,
                "timeout": timeout
            }
            if headers:
                kwargs["headers"] = headers
            if auth:
                kwargs["auth"] = auth
            if params:
                kwargs["params"] = params
            
            response = requests.request(method, url, **kwargs)
            
            # Check for HTTP errors (will raise HTTPError for 4xx/5xx status codes)
            try:
                response.raise_for_status()
            except HTTPError:
                # Re-raise to be caught by the outer exception handler
                raise
            
            return response
            
        except Timeout as e:
            self._handle_api_error(operation, url, e, logging.ERROR)
            return None
        except ConnectionError as e:
            self._handle_api_error(operation, url, e, logging.ERROR)
            return None
        except HTTPError as e:
            self._handle_api_error(operation, url, e, logging.ERROR)
            return None
        except requests.exceptions.JSONDecodeError as e:
            self._handle_api_error(operation, url, e, logging.WARNING)
            return None
        except RequestException as e:
            self._handle_api_error(operation, url, e, logging.ERROR)
            return None
        except Exception as e:
            self._handle_api_error(operation, url, e, logging.ERROR)
            return None
    
    def fetch_aliases(self):
        """Fetch all aliases from the configured gateway."""
        if self.config.gateway_type.lower() == "pfsense":
            return self._fetch_pfsense_aliases()
        elif self.config.gateway_type.lower() == "opnsense":
            return self._fetch_opnsense_aliases()
        else:
            logging.error(f"Unknown gateway type: {self.config.gateway_type}")
            return {}, {}, {}, {}
    
    def _fetch_pfsense_aliases(self):
        """Fetch all aliases from pfSense API."""
        base_url = self.config.pfs_base_url if self.config.pfs_base_url != "https://<PFS_ADDRESS>" else extract_base_url(self.config.pfs_url)
        
        logging.debug(f"pfSense base URL: {base_url}")
        
        # Fetch aliases
        alias_url = f"{base_url}/api/v2/firewall/aliases"
        logging.debug(f"Fetching aliases from: {alias_url}")
        headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
        response = self._make_api_request(
            alias_url, 
            headers=headers, 
            timeout=10, 
            operation="fetching pfSense aliases"
        )
        
        if response:
            try:
                data = response.json()
                aliases = data.get("data", []) if isinstance(data, dict) else data
                
                if not isinstance(aliases, list):
                    logging.warning(f"Unexpected aliases data format: {type(aliases)}")
                    aliases = []
                
                for alias in aliases:
                    if not isinstance(alias, dict):
                        continue
                    name = alias.get("name", "").lower()
                    alias_type = alias.get("type", "")
                    # Address is now an array in pfSense API v2
                    address_raw = alias.get("address", [])
                    # Convert to list if it's a string (backward compatibility)
                    if isinstance(address_raw, str):
                        address_list = [address_raw] if address_raw else []
                    else:
                        address_list = address_raw if isinstance(address_raw, list) else []
                    # Join addresses with comma and space
                    address_str = ", ".join(str(addr) for addr in address_list if addr)
                    description = alias.get("descr", "") or alias.get("name", "")
                    
                    # Store alias details
                    self.alias_details[name] = {
                        "name": alias.get("name", ""),
                        "type": alias_type,
                        "content": address_str,
                        "description": description
                    }
                    
                    if alias_type in ["host", "network"]:
                        self.net_map[name] = self.address_map[name] = description
                    elif alias_type == "port":
                        self.port_map[name] = address_str or description
                    else:
                        self.net_map[name] = description
                
                logging.info(f"✓ Retrieved {len(aliases)} aliases from pfSense API")
            except (ValueError, KeyError, TypeError) as e:
                logging.error(f"Error parsing pfSense aliases response: {e}")
                logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        
        # Fetch interfaces
        iface_url = f"{base_url}/api/v2/interfaces"
        headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
        response = self._make_api_request(
            iface_url, 
            headers=headers, 
            timeout=10, 
            operation="fetching pfSense interfaces"
        )
        
        if response:
            try:
                data = response.json()
                interfaces = data.get("data", []) if isinstance(data, dict) else data
                
                if not isinstance(interfaces, list):
                    logging.warning(f"Unexpected interfaces data format: {type(interfaces)}")
                    interfaces = []
                
                for iface in interfaces:
                    if not isinstance(iface, dict):
                        continue
                    # Use 'id' field (wan, lan, opt1, etc.) instead of 'if' (em0, em1, etc.)
                    identifier = iface.get("id", "")
                    descr = iface.get("descr", "")
                    if identifier:
                        identifier_lower = identifier.lower()
                        self.interface_map[identifier_lower] = descr or identifier.upper()
                
                logging.info(f"✓ Retrieved {len(interfaces)} interfaces from pfSense API")
            except (ValueError, KeyError, TypeError) as e:
                logging.warning(f"Error parsing pfSense interfaces response: {e}")
                logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        
        update_api_maps(self.interface_map, self.net_map, self.address_map, self.port_map, self.alias_details)
        return self.interface_map, self.net_map, self.address_map, self.port_map
    
    def _fetch_opnsense_aliases(self):
        """Fetch all aliases from OPNSense API."""
        base_url = self.config.opns_base_url if self.config.opns_base_url != "https://<OPNS_ADDRESS>" else extract_base_url(self.config.opns_url)
        
        logging.debug(f"OPNSense base URL: {base_url}")
        
        # Fetch aliases
        alias_url = f"{base_url}/api/firewall/alias/get"
        logging.debug(f"Fetching aliases from: {alias_url}")
        response = self._make_api_request(
            alias_url,
            auth=(self.config.opns_key, self.config.opns_secret),
            timeout=10,
            operation="fetching OPNSense aliases"
        )
        
        if response:
            try:
                data = response.json()
                # Parse the complex structure: alias.aliases.alias
                alias_container = data.get("alias", {})
                aliases_dict = alias_container.get("aliases", {})
                aliases = aliases_dict.get("alias", {}) if isinstance(aliases_dict, dict) else {}
                
                if not isinstance(aliases, dict):
                    logging.warning(f"Unexpected aliases data format: {type(aliases)}")
                    aliases = {}
                
                logging.debug(f"Found {len(aliases)} aliases in response")
                
                processed_count = 0
                for uuid, alias_data in aliases.items():
                    if not isinstance(alias_data, dict):
                        continue
                    
                    # Check if alias is enabled
                    enabled = alias_data.get("enabled", "0")
                    if enabled != "1":
                        logging.debug(f"Skipping disabled alias: {alias_data.get('name', uuid)}")
                        continue
                    
                    alias_name = alias_data.get("name", "")
                    if not alias_name:
                        continue
                    
                    name = alias_name.lower()
                    description = alias_data.get("description", "") or alias_name
                    
                    # Determine alias type by checking which type has selected=1
                    type_info = alias_data.get("type", {})
                    if not isinstance(type_info, dict):
                        continue
                    
                    alias_type = None
                    for type_key, type_value in type_info.items():
                        if isinstance(type_value, dict) and type_value.get("selected", 0) == 1:
                            alias_type = type_key
                            break
                    
                    # Only process host, network, and port types
                    if alias_type not in ["host", "network", "port"]:
                        logging.debug(f"Skipping alias '{alias_name}' with unsupported type: {alias_type}")
                        continue
                    
                    # Extract content values (items with selected=1)
                    content = alias_data.get("content", {})
                    content_values = []
                    if isinstance(content, dict):
                        for content_key, content_item in content.items():
                            if isinstance(content_item, dict) and content_item.get("selected", 0) == 1:
                                value = content_item.get("value", content_key)
                                if value:
                                    content_values.append(str(value))
                    
                    content_str = ", ".join(content_values) if content_values else ""
                    
                    # Store alias details
                    self.alias_details[name] = {
                        "name": alias_name,
                        "type": alias_type,
                        "content": content_str,
                        "description": description
                    }
                    
                    # Map to appropriate dictionaries
                    if alias_type in ["host", "network"]:
                        self.net_map[name] = self.address_map[name] = description
                        logging.debug(f"Mapped {alias_type} alias '{alias_name}': {description} (content: {content_str})")
                    elif alias_type == "port":
                        self.port_map[name] = content_str or description
                        logging.debug(f"Mapped port alias '{alias_name}': {content_str or description}")
                    
                    processed_count += 1
                
                logging.info(f"✓ Retrieved {processed_count} aliases from OPNSense API (host/network/port types only)")
            except (ValueError, KeyError, TypeError) as e:
                logging.error(f"Error parsing OPNSense aliases response: {e}")
                logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        
        # Fetch interfaces using the correct endpoint
        iface_url = f"{base_url}/api/interfaces/overview/interfaces_info"
        response = self._make_api_request(
            iface_url,
            auth=(self.config.opns_key, self.config.opns_secret),
            timeout=10,
            operation="fetching OPNSense interfaces"
        )
        
        if response:
            try:
                data = response.json()
                rows = data.get("rows", []) if isinstance(data, dict) else []
                
                if not isinstance(rows, list):
                    logging.warning(f"Unexpected interfaces data format: {type(rows)}")
                    rows = []
                
                for row in rows:
                    if isinstance(row, dict):
                        identifier = row.get("identifier", "").lower()
                        description = row.get("description", "") or row.get("descr", "")
                        enabled = row.get("enabled", False)
                        
                        # Skip system interfaces and disabled interfaces
                        if (identifier and 
                            identifier not in ["lo0", "enc0", "pflog0", ""] and
                            enabled):
                            self.interface_map[identifier] = description if description else identifier.upper()
                            logging.debug(f"Mapped interface: {identifier} -> {description or identifier.upper()}")
                
                logging.info(f"✓ Retrieved {len(self.interface_map)} interfaces from OPNSense API")
            except (ValueError, KeyError, TypeError) as e:
                logging.warning(f"Error parsing OPNSense interfaces response: {e}")
                logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        
        update_api_maps(self.interface_map, self.net_map, self.address_map, self.port_map, self.alias_details)
        return self.interface_map, self.net_map, self.address_map, self.port_map
    
    def fetch_rules(self):
        """Fetch firewall rules from the configured gateway."""
        if self.config.gateway_type.lower() == "pfsense":
            return self._fetch_pfsense_rules()
        elif self.config.gateway_type.lower() == "opnsense":
            return self._fetch_opnsense_rules()
        else:
            logging.error(f"Unknown gateway type: {self.config.gateway_type}")
            return []
    
    def _fetch_pfsense_rules(self):
        """Fetch firewall rules from pfSense."""
        # Auto-detect interfaces if not specified
        interfaces_to_process = self.config.interfaces.copy() if self.config.interfaces else []
        if not interfaces_to_process:
            logging.info("Attempting auto-detection of interfaces...")
            detected = self._detect_pfsense_interfaces()
            if detected:
                interfaces_to_process = detected
                logging.info(f"✓ {len(interfaces_to_process)} interfaces detected: {interfaces_to_process}")
            else:
                logging.warning("Could not auto-detect interfaces. Will fetch all rules globally.")
                logging.warning("To improve accuracy, please specify interfaces in config.py: INTERFACES = ['wan', 'lan', 'opt1', ...]")
                # Continue anyway - we'll fetch all rules globally
                interfaces_to_process = []
        else:
            logging.info(f"Using {len(interfaces_to_process)} manually specified interfaces: {interfaces_to_process}")
        
        all_entries = []
        seen_rule_ids = set()
        
        # Method 1: Global rules (always try this first)
        logging.debug(f"Fetching pfSense global rules from: {self.config.pfs_url}")
        headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
        response = self._make_api_request(
            self.config.pfs_url,
            headers=headers,
            timeout=30,
            operation="fetching pfSense global rules"
        )
        
        if response:
            try:
                data = response.json()
                all_rules = data.get("data", [])
                
                if not isinstance(all_rules, list):
                    logging.warning(f"Unexpected rules data format: {type(all_rules)}")
                    all_rules = []
                
                logging.info(f"  → {len(all_rules)} global rules retrieved")
                
                if not all_rules:
                    logging.warning("No rules found in global response. Check API credentials and URL.")
                    logging.debug(f"Response data: {data}")
                
                for entry in all_rules:
                    if not isinstance(entry, dict):
                        continue
                    rule_id = entry.get("tracker") or entry.get("id") or f"{entry.get('sequence', '')}{entry.get('interface', '')}"
                    if rule_id and rule_id not in seen_rule_ids:
                        seen_rule_ids.add(rule_id)
                        all_entries.append(entry)
            except (ValueError, KeyError, TypeError) as e:
                logging.error(f"Error parsing pfSense rules response: {e}")
                logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        
        # Method 2: Per-interface rules (if interfaces were specified or detected)
        if interfaces_to_process:
            for interface in interfaces_to_process:
                logging.info(f"Fetching rules for interface: {interface}")
                logging.debug(f"Fetching rules for interface {interface} from: {self.config.pfs_url}")
                # Note: pfSense API may support interface filtering via query params
                # Adjust URL if needed based on pfSense API documentation
                headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
                params = {"interface": interface} if hasattr(self.config, 'pfs_url') else {}
                response = self._make_api_request(
                    self.config.pfs_url,
                    headers=headers,
                    params=params,
                    timeout=30,
                    operation=f"fetching pfSense rules for interface {interface}"
                )
                
                if response:
                    try:
                        data = response.json()
                        entries = data.get("data", [])
                        
                        if not isinstance(entries, list):
                            logging.warning(f"Unexpected rules data format for {interface}: {type(entries)}")
                            entries = []
                        
                        # Filter entries by interface if API doesn't support filtering
                        if entries:
                            filtered_entries = [e for e in entries if isinstance(e, dict) and e.get("interface", "").lower() == interface.lower()]
                            entries = filtered_entries
                        logging.info(f"  → {len(entries)} rules found for {interface}")
                        
                        for entry in entries:
                            if not isinstance(entry, dict):
                                continue
                            rule_id = entry.get("tracker") or entry.get("id") or f"{entry.get('sequence', '')}{entry.get('interface', '')}"
                            if rule_id and rule_id not in seen_rule_ids:
                                seen_rule_ids.add(rule_id)
                                all_entries.append(entry)
                    except (ValueError, KeyError, TypeError) as e:
                        logging.warning(f"Error parsing pfSense rules response for {interface}: {e}")
                        logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        else:
            logging.info("No specific interfaces to process, using global rules only")
        
        if all_entries:
            logging.info(f"✓ Total of {len(all_entries)} unique rules retrieved")
        else:
            logging.error("No rules retrieved. Please check:")
            logging.error("  1. API credentials are correct")
            logging.error("  2. API URL is correct")
            logging.error("  3. Firewall allows API access from this IP")
            logging.error("  4. Run with --debug flag for more details")
        
        return all_entries
    
    def _fetch_opnsense_rules(self):
        """Fetch firewall rules from OPNSense."""
        # Auto-detect interfaces if not specified
        interfaces_to_process = self.config.interfaces.copy() if self.config.interfaces else []
        if not interfaces_to_process:
            logging.info("Attempting auto-detection of interfaces...")
            detected = self._detect_opnsense_interfaces()
            if detected:
                interfaces_to_process = detected
                logging.info(f"✓ {len(interfaces_to_process)} interfaces detected: {interfaces_to_process}")
            else:
                logging.warning("Could not auto-detect interfaces. Will fetch all rules globally.")
                logging.warning("To improve accuracy, please specify interfaces in config.py: INTERFACES = ['wan', 'lan', 'opt1', ...]")
                # Continue anyway - we'll fetch all rules globally
                interfaces_to_process = []
        else:
            logging.info(f"Using {len(interfaces_to_process)} manually specified interfaces: {interfaces_to_process}")
        
        all_entries = []
        seen_rule_ids = set()
        
        # Method 1: Global rules (always try this first)
        logging.debug(f"Fetching OPNSense global rules from: {self.config.opns_url}")
        params = {"show_all": "1"}
        response = self._make_api_request(
            self.config.opns_url,
            params=params,
            auth=(self.config.opns_key, self.config.opns_secret),
            timeout=30,
            operation="fetching OPNSense global rules"
        )
        
        if response:
            try:
                data = response.json()
                all_rules = data.get("rows", [])
                
                if not isinstance(all_rules, list):
                    logging.warning(f"Unexpected rules data format: {type(all_rules)}")
                    all_rules = []
                
                logging.info(f"  → {len(all_rules)} global rules retrieved")
                
                if not all_rules:
                    logging.warning("No rules found in global response. Check API credentials and URL.")
                    logging.debug(f"Response data: {data}")
                
                for entry in all_rules:
                    if not isinstance(entry, dict):
                        continue
                    rule_id = entry.get("uuid") or f"{entry.get('sequence', '')}{entry.get('interface', '')}"
                    if rule_id and rule_id not in seen_rule_ids:
                        seen_rule_ids.add(rule_id)
                        all_entries.append(entry)
            except (ValueError, KeyError, TypeError) as e:
                logging.error(f"Error parsing OPNSense rules response: {e}")
                logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        
        # Method 2: Per-interface rules (if interfaces were specified or detected)
        if interfaces_to_process:
            for interface in interfaces_to_process:
                logging.info(f"Fetching rules for interface: {interface}")
                logging.debug(f"Fetching rules for interface {interface} from: {self.config.opns_url}")
                params = {"interface": interface, "show_all": "1"}
                response = self._make_api_request(
                    self.config.opns_url,
                    params=params,
                    auth=(self.config.opns_key, self.config.opns_secret),
                    timeout=30,
                    operation=f"fetching OPNSense rules for interface {interface}"
                )
                
                if response:
                    try:
                        data = response.json()
                        entries = data.get("rows", [])
                        
                        if not isinstance(entries, list):
                            logging.warning(f"Unexpected rules data format for {interface}: {type(entries)}")
                            entries = []
                        
                        logging.info(f"  → {len(entries)} rules found for {interface}")
                        
                        for entry in entries:
                            if not isinstance(entry, dict):
                                continue
                            rule_id = entry.get("uuid") or f"{entry.get('sequence', '')}{entry.get('interface', '')}"
                            if rule_id and rule_id not in seen_rule_ids:
                                seen_rule_ids.add(rule_id)
                                all_entries.append(entry)
                    except (ValueError, KeyError, TypeError) as e:
                        logging.warning(f"Error parsing OPNSense rules response for {interface}: {e}")
                        logging.debug(f"Response data: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
        else:
            logging.info("No specific interfaces to process, using global rules only")
        
        if all_entries:
            logging.info(f"✓ Total of {len(all_entries)} unique rules retrieved")
        else:
            logging.error("No rules retrieved. Please check:")
            logging.error("  1. API credentials are correct")
            logging.error("  2. API URL is correct")
            logging.error("  3. Firewall allows API access from this IP")
            logging.error("  4. Run with --debug flag for more details")
        
        return all_entries
    
    def _detect_pfsense_interfaces(self):
        """Auto-detect interface list from pfSense."""
        interfaces = set()
        base_api_url = self.config.pfs_base_url if self.config.pfs_base_url != "https://<PFS_ADDRESS>" else extract_base_url(self.config.pfs_url)
        
        logging.debug(f"Attempting interface detection with base URL: {base_api_url}")
        
        # Primary method: Use the correct pfSense endpoint
        endpoint = "/api/v2/interfaces"
        url = f"{base_api_url}{endpoint}"
        logging.debug(f"Trying primary endpoint: {url}")
        headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
        response = self._make_api_request(
            url,
            headers=headers,
            timeout=10,
            operation="detecting pfSense interfaces (primary method)"
        )
        
        if response:
            try:
                data = response.json()
                logging.debug(f"Response data structure: {type(data)}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
                
                interfaces_list = data.get("data", []) if isinstance(data, dict) else data
                
                if not isinstance(interfaces_list, list):
                    logging.warning(f"Unexpected interfaces data format: {type(interfaces_list)}")
                    interfaces_list = []
                
                logging.debug(f"Found {len(interfaces_list)} interface entries")
                
                for iface in interfaces_list:
                    if isinstance(iface, dict):
                        # Get interface identifier (id field: wan, lan, opt1, etc.)
                        identifier = iface.get("id", "")
                        # Get description
                        descr = iface.get("descr", "")
                        # Check if interface is enabled
                        enabled = iface.get("enable", True)  # Default to True if not specified
                        
                        # Only add enabled interfaces, skip system interfaces
                        if (identifier and 
                            identifier.lower() not in ["lo0", "enc0", "pflog0", ""] and
                            enabled):
                            identifier_lower = identifier.lower()
                            logging.debug(f"Found enabled interface: {identifier_lower} ({descr})")
                            interfaces.add(identifier_lower)
            except (ValueError, KeyError, TypeError) as e:
                logging.debug(f"Error parsing pfSense interfaces response: {e}")
        
        # Fallback method: Try v1 endpoint
        if not interfaces:  # Only try fallback if primary method didn't find interfaces
            endpoint = "/api/v1/firewall/interface"
            url = f"{base_api_url}{endpoint}"
            logging.debug(f"Trying fallback endpoint: {url}")
            headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
            response = self._make_api_request(
                url,
                headers=headers,
                timeout=10,
                operation="detecting pfSense interfaces (fallback method)"
            )
            
            if response:
                try:
                    data = response.json()
                    if isinstance(data, dict):
                        interfaces_list = data.get("data", [])
                        if isinstance(interfaces_list, list):
                            for iface in interfaces_list:
                                if isinstance(iface, dict):
                                    if_name = iface.get("if", "").lower()
                                    if if_name and if_name not in ["lo0", "enc0", "pflog0"]:
                                        logging.debug(f"Found interface from fallback endpoint: {if_name}")
                                        interfaces.add(if_name)
                except (ValueError, KeyError, TypeError) as e:
                    logging.debug(f"Error parsing pfSense interfaces fallback response: {e}")
        
        # Extract from firewall rules (most reliable method)
        if not interfaces:  # Only try this if other methods didn't find interfaces
            logging.debug("Attempting to extract interfaces from firewall rules...")
            logging.debug(f"Fetching rules from: {self.config.pfs_url}")
            headers = {"accept": "application/json", "X-API-Key": self.config.pfs_token}
            response = self._make_api_request(
                self.config.pfs_url,
                headers=headers,
                timeout=10,
                operation="extracting interfaces from pfSense rules"
            )
            
            if response:
                try:
                    data = response.json()
                    logging.debug(f"Rules response structure: {type(data)}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
                    
                    rules = data.get("data", [])
                    
                    if not isinstance(rules, list):
                        logging.warning(f"Unexpected rules data format: {type(rules)}")
                        rules = []
                    
                    logging.debug(f"Found {len(rules)} rule entries")
                    
                    for i, entry in enumerate(rules):
                        if isinstance(entry, dict):
                            # Check interface field
                            if "interface" in entry and entry["interface"]:
                                iface = entry["interface"].lower()
                                logging.debug(f"Rule {i}: interface = {iface}")
                                interfaces.add(iface)
                            # Also check source/destination for interface references
                            for field in ["source", "destination"]:
                                if field in entry and isinstance(entry[field], dict):
                                    for subfield in ["network", "address"]:
                                        if subfield in entry[field] and entry[field][subfield]:
                                            val = str(entry[field][subfield]).lower()
                                            if val in ["wan", "lan"] or val.startswith("opt"):
                                                logging.debug(f"Rule {i}: found interface in {field}.{subfield}: {val}")
                                                interfaces.add(val)
                except (ValueError, KeyError, TypeError) as e:
                    logging.debug(f"Error parsing pfSense rules for interface extraction: {e}")
        
        logging.debug(f"All collected interface candidates: {sorted(interfaces)}")
        
        # Filter and sort valid interfaces
        valid_interfaces = []
        for iface in interfaces:
            iface_str = str(iface).lower().strip()
            # Ignore invalid values
            if iface_str and iface_str not in ["1", "any", "(self)", "", "none", "null"]:
                # Accept standard interface names
                if iface_str in ["wan", "lan"] or iface_str.startswith("opt"):
                    valid_interfaces.append(iface_str)
                    logging.debug(f"Accepted interface: {iface_str}")
                else:
                    logging.debug(f"Rejected interface candidate: {iface_str} (doesn't match pattern)")
        
        valid_interfaces = sorted(list(set(valid_interfaces)))
        
        if valid_interfaces:
            logging.info(f"✓ Auto-detected interfaces: {valid_interfaces}")
            return valid_interfaces
        
        logging.warning(f"No valid interfaces auto-detected. Collected candidates were: {sorted(interfaces)}")
        logging.warning("Please manually specify interfaces in config.py: INTERFACES = ['wan', 'lan', 'opt1', ...]")
        return []
    
    def _detect_opnsense_interfaces(self):
        """Auto-detect interface list from OPNSense."""
        interfaces = set()
        base_api_url = self.config.opns_base_url if self.config.opns_base_url != "https://<OPNS_ADDRESS>" else extract_base_url(self.config.opns_url)
        
        logging.debug(f"Attempting interface detection with base URL: {base_api_url}")
        
        # Primary method: Use the correct OPNSense endpoint
        endpoint = "/api/interfaces/overview/interfaces_info"
        url = f"{base_api_url}{endpoint}"
        logging.debug(f"Trying primary endpoint: {url}")
        response = self._make_api_request(
            url,
            auth=(self.config.opns_key, self.config.opns_secret),
            timeout=10,
            operation="detecting OPNSense interfaces (primary method)"
        )
        
        if response:
            try:
                data = response.json()
                logging.debug(f"Response data structure: {type(data)}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
                
                if isinstance(data, dict) and "rows" in data:
                    rows = data.get("rows", [])
                    
                    if not isinstance(rows, list):
                        logging.warning(f"Unexpected interfaces data format: {type(rows)}")
                        rows = []
                    
                    logging.debug(f"Found {len(rows)} interface entries in 'rows'")
                    
                    for row in rows:
                        if isinstance(row, dict):
                            # Get identifier (wan, lan, etc.)
                            identifier = row.get("identifier", "")
                            enabled = row.get("enabled", False)
                            
                            # Only add enabled interfaces, skip system interfaces
                            if (identifier and 
                                identifier not in ["lo0", "enc0", "pflog0", ""] and
                                enabled):
                                logging.debug(f"Found enabled interface identifier: {identifier}")
                                interfaces.add(identifier)
                            
                            # Also check config.if for device name mapping (as fallback)
                            config = row.get("config", {})
                            if isinstance(config, dict):
                                if_name = config.get("if", "")
                                if (if_name and 
                                    if_name not in ["lo0", "enc0", "pflog0"] and
                                    enabled and
                                    not identifier):  # Only use if no identifier found
                                    logging.debug(f"Using device name as fallback: {if_name}")
                                    interfaces.add(if_name)
            except (ValueError, KeyError, TypeError) as e:
                logging.debug(f"Error parsing OPNSense interfaces response: {e}")
        

        
        # Extract from firewall rules (most reliable method)
        if not interfaces:  # Only try this if primary method didn't find interfaces
            logging.debug("Attempting to extract interfaces from firewall rules...")
            params = {"show_all": "1"}
            logging.debug(f"Fetching rules from: {self.config.opns_url}")
            response = self._make_api_request(
                self.config.opns_url,
                params=params,
                auth=(self.config.opns_key, self.config.opns_secret),
                timeout=10,
                operation="extracting interfaces from OPNSense rules"
            )
            
            if response:
                try:
                    data = response.json()
                    logging.debug(f"Rules response structure: {type(data)}, keys: {list(data.keys()) if isinstance(data, dict) else 'N/A'}")
                    
                    rows = data.get("rows", [])
                    
                    if not isinstance(rows, list):
                        logging.warning(f"Unexpected rules data format: {type(rows)}")
                        rows = []
                    
                    logging.debug(f"Found {len(rows)} rule entries")
                    
                    for i, entry in enumerate(rows):
                        if isinstance(entry, dict):
                            if "interface" in entry and entry["interface"]:
                                iface = entry["interface"]
                                logging.debug(f"Rule {i}: interface = {iface}")
                                interfaces.add(iface)
                            # Also check source/destination for interface references
                            for field in ["source", "destination"]:
                                if field in entry and isinstance(entry[field], dict):
                                    for subfield in ["network", "address"]:
                                        if subfield in entry[field] and entry[field][subfield]:
                                            val = str(entry[field][subfield]).lower()
                                            if val in ["wan", "lan"] or val.startswith("opt"):
                                                logging.debug(f"Rule {i}: found interface in {field}.{subfield}: {val}")
                                                interfaces.add(val)
                except (ValueError, KeyError, TypeError) as e:
                    logging.debug(f"Error parsing OPNSense rules for interface extraction: {e}")
        
        logging.debug(f"All collected interface candidates: {sorted(interfaces)}")
        
        # Filter and sort valid interfaces
        valid_interfaces = []
        for iface in interfaces:
            iface_str = str(iface).lower().strip()
            # Ignore invalid values
            if iface_str and iface_str not in ["1", "any", "(self)", "", "none", "null"]:
                # Accept standard interface names
                if iface_str in ["wan", "lan"] or iface_str.startswith("opt"):
                    valid_interfaces.append(iface_str)
                    logging.debug(f"Accepted interface: {iface_str}")
                else:
                    logging.debug(f"Rejected interface candidate: {iface_str} (doesn't match pattern)")
        
        valid_interfaces = sorted(list(set(valid_interfaces)))
        
        if valid_interfaces:
            logging.info(f"✓ Auto-detected interfaces: {valid_interfaces}")
            return valid_interfaces
        
        logging.warning(f"No valid interfaces auto-detected. Collected candidates were: {sorted(interfaces)}")
        logging.warning("Please manually specify interfaces in config.py: INTERFACES = ['wan', 'lan', 'opt1', ...]")
        return []

