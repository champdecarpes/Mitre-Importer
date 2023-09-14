export interface Table {
  name: string;
  x_mitre_shortname: string;
  external_id: string;
  external_url: string;
  techniques: Technique[];
}

export interface Technique {
  name: string;
  siem_exist: string;
  siem_exist_count: number;
  external_id: string;
  external_url: string;
  kill_chain_phase: KillChainPhase[];
  sub_techniques: SubTechnique[];
}

export interface SubTechnique {
  name: string;
  siem_exist: string;
  external_main_id: string;
  external_id: string;
  external_url: string;
  kill_chain_phase: KillChainPhase[];
}

export interface KillChainPhase {
  kill_chain_name: string;
  phase_name: string;
}

export interface SocData {
  data: string[];
}
