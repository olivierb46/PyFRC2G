"""
CISO Assistant client module for PyFRC2G
Handles uploading generated PDFs to CISO Assistant as evidence revisions
"""

import os
import logging
import traceback
import requests
import urllib3
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CISOCClient:
    """Client for uploading evidence to CISO Assistant"""
    
    def __init__(self, config):
        """
        Initialize CISO Assistant client.
        
        Args:
            config: Config object with CISO Assistant settings
        """
        self.config = config
        self.ciso_url = getattr(config, 'ciso_url', None)
        self.ciso_token = getattr(config, 'ciso_token', None)
        self.ciso_evidence_path = getattr(config, 'ciso_evidence_path', None)
        self.ciso_folder_id = getattr(config, 'ciso_folder_id', None)
        self.ciso_evidence_id = getattr(config, 'ciso_evidence_id', None)
        
        # Check if CISO Assistant is configured
        self.enabled = (
            self.ciso_url and 
            self.ciso_url != "https://<CISO_ASSISTANT_ADDRESS>" and
            self.ciso_token and 
            self.ciso_token != "<CISO_ASSISTANT_TOKEN>" and
            self.ciso_evidence_path and
            self.ciso_folder_id and
            self.ciso_folder_id != "<CISO_FOLDER_ID>" and
            self.ciso_evidence_id and
            self.ciso_evidence_id != "<CISO_EVIDENCE_ID>"
        )
        
        if not self.enabled:
            logging.debug("CISO Assistant not configured or disabled")
        else:
            logging.debug(f"CISO Assistant configured: URL={self.ciso_url}, Evidence Path={self.ciso_evidence_path}")
    
    def upload_pdf(self, pdf_path):
        """
        Upload a PDF file to CISO Assistant as an evidence revision.
        
        Args:
            pdf_path: Path to the PDF file to upload
            
        Returns:
            bool: True if upload successful, False otherwise
        """
        if not self.enabled:
            logging.debug("CISO Assistant not enabled, skipping upload")
            return False
        
        if not os.path.exists(pdf_path):
            logging.error(f"PDF file not found: {pdf_path}")
            return False
        
        try:
            # Prepare the file for upload
            pdf_filename = os.path.basename(pdf_path)
            logging.info(f"Uploading {pdf_filename} to CISO Assistant...")
            
            with open(pdf_path, 'rb') as pdf_file:
                files = {
                    'attachment': (pdf_filename, pdf_file, 'application/pdf')
                }
                
                data = {
                    "is_published": True,
                    "observation": "Automatically generated evidence",
                    "folder": self.ciso_folder_id,
                    "evidence": self.ciso_evidence_id
                }
                
                headers = {
                    'Authorization': f'Token {self.ciso_token}'
                }
                
                # Make the upload request
                response = requests.post(
                    self.ciso_evidence_path,
                    files=files,
                    data=data,
                    headers=headers,
                    verify=False,  # CISO Assistant might use self-signed certificates
                    timeout=60  # Large files might take time
                )
                
                # Check response
                response.raise_for_status()
                
                logging.info(f"✓ Successfully uploaded {pdf_filename} to CISO Assistant")
                logging.debug(f"Response: {response.status_code} - {response.text[:200] if response.text else 'No response body'}")
                return True
                
        except Timeout as e:
            logging.error(f"Timeout while uploading {pdf_path} to CISO Assistant: {e}")
            return False
        except ConnectionError as e:
            logging.error(f"Connection error while uploading {pdf_path} to CISO Assistant: {e}")
            logging.error("Check that CISO Assistant is accessible and the URL is correct")
            return False
        except HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') and e.response else 'Unknown'
            if status_code == 401:
                logging.error("Authentication failed. Check your CISO Assistant token.")
            elif status_code == 403:
                logging.error("Access forbidden. Check your CISO Assistant permissions.")
            elif status_code == 404:
                logging.error(f"Evidence endpoint not found. Check the evidence ID in the URL: {self.ciso_evidence_url}")
            else:
                logging.error(f"HTTP error {status_code} while uploading to CISO Assistant: {e}")
            logging.debug(f"Response: {e.response.text[:500] if hasattr(e, 'response') and e.response else 'N/A'}")
            return False
        except RequestException as e:
            logging.error(f"Request error while uploading {pdf_path} to CISO Assistant: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error while uploading {pdf_path} to CISO Assistant: {e}")
            logging.debug(f"Full traceback:\n{traceback.format_exc()}")
            return False
    
    def upload_global_pdf(self, global_pdf_path):
        """
        Upload the global PDF file in the output directory to CISO Assistant.
        
        Args:
            global_pdf_path: global PDF path to upload
            
        Returns:
            dict: Statistics about upload (successful, failed)
        """
        if not self.enabled:
            logging.debug("CISO Assistant not enabled, skipping uploads")
            return {"successful": 0, "failed": 0, "total": 0}
        
        if not os.path.exists(global_pdf_path):
            logging.warning(f"Global PDF not found: {global_pdf_path}")
            return {"successful": 0, "failed": 0, "total": 0}
        
        stats = {"successful": 0, "failed": 0}

        if self.upload_pdf(global_pdf_path):
            stats["successful"] = 1
        else:
            stats["failed"] = 1
        
        logging.info(f"CISO Assistant upload complete: {stats['successful']} successful")

        return stats
