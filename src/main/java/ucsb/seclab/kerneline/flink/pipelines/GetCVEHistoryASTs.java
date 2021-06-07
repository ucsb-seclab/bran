package ucsb.seclab.kerneline.flink.pipelines;

import org.apache.flink.api.common.functions.RichMapFunction;
import org.apache.flink.configuration.Configuration;

import ucsb.seclab.kerneline.model.CVEHistory;

public class GetCVEHistoryASTs extends RichMapFunction<CVEHistory, CVEHistory>{
	
	@Override 
	public void open(Configuration config) {
		
	}
	
	@Override
	public void close() {
		
	}
	
	@Override
	public CVEHistory map(CVEHistory value) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}
}
